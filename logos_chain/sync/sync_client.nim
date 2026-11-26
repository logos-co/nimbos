# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  std/sequtils,
  bincode,
  chronicles,
  chronos,
  libp2p/switch,
  stew/byteutils as sbyteutils,
  ../chain/block_processor,
  ./[framing, syncer_types, types]

from ../chain/local_tree import
  LocalTree, localTipId, latestImmutableBlockId, hasBlock
from ../core/types import Block, BlockId, blockId
from libp2p/crypto/ed25519/ed25519 import EdPublicKeySize, toBytes

export types, block_processor, syncer_types

logScope:
  topics = "cryptarchia_sync"

const
  GetTipTimeout = 5.seconds
    ## Per-peer deadline for a `GetTip` exchange during IBD.
  DownloadStreamTimeout = 10.seconds
    ## Per-step deadline for dialing, writing, and reading each sync stream frame.
  IbdRoundDelay = 1.seconds
    ## Delay between rounds of Initial Block Download (`T_round` in spec).
  MaxTipRetries = 4
    ## Maximum exponential-backoff retries when no IBD peer returns a tip.

proc requestTip(
    syncer: Syncer,
    peer: PeerId,
): Future[Opt[GetTipResponse]] {.async: (raises: [CancelledError]).} =
  var wireReq: seq[byte]
  debug "IBD GetTip request", peer, protocol = syncer.chainSyncProtocol
  try:
    wireReq = encode(
      RequestMessage(kind: rmGetTip), cryptarchiaSyncBincodeConfig)
    debug "IBD GetTip serialize ok", peer, requestBytes = wireReq.len
  except BincodeError:
    debug "IBD GetTip serialize failed", peer, exc = getCurrentExceptionMsg()
    return Opt.none(GetTipResponse)
  var conn: Connection
  try:
    debug "IBD GetTip dialing",
      peer,
      protocol = syncer.chainSyncProtocol,
      peerConnected = syncer.sw.isConnected(peer)
    conn = await syncer.sw.dial(peer, syncer.chainSyncProtocol)
    debug "IBD GetTip dial ok", peer, protocol = conn.protocol
  except DialFailedError as exc:
    debug "IBD GetTip dial failed", peer, exc = exc.msg, peerConnected = syncer.sw.isConnected(peer)
    return Opt.none(GetTipResponse)
  try:
    await writeCryptarchiaPrefixedInner(conn, wireReq)
    debug "IBD GetTip write ok", peer, requestBytes = wireReq.len
    let p = (await readCryptarchiaPrefixedInner(conn)).valueOr:
      debug "IBD GetTip response read failed", peer
      return Opt.none(GetTipResponse)
    debug "IBD GetTip read ok", peer, responseBytes = p.len
    try:
      let resp = decode(p, GetTipResponse, cryptarchiaSyncBincodeConfig)
      case resp.kind
      of gtrTip:
        debug "IBD GetTip deserialize ok",
          peer,
          tip = sbyteutils.toHex(resp.tipData.tip),
          height = resp.tipData.height
      of gtrFailure:
        debug "IBD GetTip deserialize ok (peer failure)",
          peer,
          reason = resp.failureMessage
      debug "IBD GetTip exchange complete", peer
      return Opt.some(resp)
    except BincodeError as exc:
      debug "IBD GetTip deserialize failed", peer, exc = exc.msg
      return Opt.none(GetTipResponse)
  except BincodeError as exc:
    debug "IBD GetTip exchange failed", peer, exc = exc.msg
    return Opt.none(GetTipResponse)
  except LPStreamError as exc:
    debug "IBD GetTip exchange failed", peer, exc = exc.msg
    return Opt.none(GetTipResponse)
  finally:
    await noCancel conn.close()

proc sendGetTipRequest*(
    syncer: Syncer,
    peer: PeerId,
    timeout: Duration,
): Future[Opt[GetTipResponse]] {.async: (raises: [CancelledError]).} =
  if timeout <= ZeroDuration:
    debug "IBD GetTip timed out", peer, timeout
    return Opt.none(GetTipResponse)
  let fut = requestTip(syncer, peer)
  try:
    if not await fut.withTimeout(timeout):
      debug "IBD GetTip timed out", peer, timeout
      return Opt.none(GetTipResponse)
    await fut
  except CancelledError as exc:
    await cancelAndWait(fut)
    raise exc

func buildKnownBlocks*(
    localTree: LocalTree,
    additionalBlocks: openArray[BlockId],
): KnownBlocks =
  let takeCount = min(additionalBlocks.len, MaxKnownAdditionalBlocks)
  KnownBlocks(
    localTip: localTipId(localTree),
    latestImmutableBlock: latestImmutableBlockId(localTree),
    additionalBlocks: @(additionalBlocks.toOpenArray(0, takeCount - 1)),
  )

func decodeSyncBlock*(wire: openArray[byte]): Result[Block, string] =
  # Decodes a sync-wire block; `UncleHeaders` and `BlockTxs` bound both lists.
  try:
    ok(decode(wire, Block, cryptarchiaSyncBincodeConfig))
  except BincodeError as exc:
    err(exc.msg)

proc encodeDownloadReq(
    peer: PeerId,
    localTree: LocalTree,
    targetBlock: BlockId,
    latestDownloadedId: Opt[BlockId],
): Opt[seq[byte]] =
  var knownBlocks = buildKnownBlocks(localTree, [])
  for id in latestDownloadedId:
    knownBlocks.additionalBlocks.add(id)
  debug "Sync download blocks request",
    peer,
    targetBlock = sbyteutils.toHex(targetBlock),
    localTip = sbyteutils.toHex(knownBlocks.localTip),
    latestImmutable = sbyteutils.toHex(knownBlocks.latestImmutableBlock),
    additionalKnown = knownBlocks.additionalBlocks.len
  try:
    let wireReq = encode(
      RequestMessage(
        kind: rmDownloadBlocksRequest,
        downloadBlocksRequest: DownloadBlocksRequest(
          targetBlock: targetBlock,
          knownBlocks: knownBlocks,
        ),
      ),
      cryptarchiaSyncBincodeConfig,
    )
    debug "Sync download serialize ok", peer, requestBytes = wireReq.len
    Opt.some(wireReq)
  except BincodeError as exc:
    debug "Sync download serialize failed", peer, exc = exc.msg
    Opt.none(seq[byte])

proc openDownloadStream(
    syncer: Syncer,
    peer: PeerId,
    targetBlock: BlockId,
    latestDownloadedId: Opt[BlockId],
    timeout: Duration,
): Future[Opt[Connection]] {.async: (raises: [CancelledError]).} =
  if timeout <= ZeroDuration:
    debug "Sync download timed out", peer, timeout
    return Opt.none(Connection)
  let wireReq = encodeDownloadReq(peer, syncer.localTree, targetBlock, latestDownloadedId).valueOr:
    return Opt.none(Connection)
  var conn: Connection
  try:
    debug "Sync download dialing",
      peer,
      protocol = syncer.chainSyncProtocol,
      peerConnected = syncer.sw.isConnected(peer)
    let dialFut = syncer.sw.dial(peer, syncer.chainSyncProtocol)
    if not await dialFut.withTimeout(timeout):
      debug "Sync download dial timed out", peer, timeout
      return Opt.none(Connection)
    conn = await dialFut
    debug "Sync download dial ok", peer, protocol = conn.protocol
  except DialFailedError as exc:
    debug "Sync download dial failed", peer, exc = exc.msg, peerConnected = syncer.sw.isConnected(peer)
    return Opt.none(Connection)
  var ready = false
  defer:
    if not ready:
      await noCancel conn.close()
  try:
    let writeFut = writeCryptarchiaPrefixedInner(conn, wireReq)
    if not await writeFut.withTimeout(timeout):
      debug "Sync download write timed out", peer, timeout
      return Opt.none(Connection)
    await writeFut
    debug "Sync download write ok", peer, requestBytes = wireReq.len
    ready = true
    Opt.some(conn)
  except BincodeError as exc:
    debug "Sync download exchange failed", peer, exc = exc.msg
    return Opt.none(Connection)
  except LPStreamError as exc:
    debug "Sync download exchange failed", peer, exc = exc.msg
    return Opt.none(Connection)

proc parseDownloadFrame(
    peer: PeerId,
    blocksRead: int,
    innerOpt: Opt[seq[byte]],
): Result[Opt[Block], void] =
  template inner: untyped =
    innerOpt.valueOr:
      debug "Sync: download stream read failed", peer, blocksRead
      return err()
  let msg =
    try:
      decode(inner, DownloadBlocksResponse, cryptarchiaSyncBincodeConfig)
    except BincodeError as exc:
      debug "Sync: download frame decode failed", peer, exc = exc.msg
      return err()
  case msg.kind
  of dbrFailure:
    debug "Sync: download stream failed", peer, reason = msg.blocksUnavailableReason
    err()
  of dbrNoMoreBlocks:
    debug "Sync: download stream no more blocks", peer, blocksRead
    ok(Opt.none(Block))
  of dbrBlock:
    let blk = decodeSyncBlock(msg.downloadedBlock).valueOr:
      debug "Sync: block decode failed", peer, reason = error
      return err()
    ok(Opt.some(blk))

proc downloadBlocks*(
    syncer: Syncer,
    peer: PeerId,
    targetBlock: BlockId,
    latestDownloadedId = Opt.none(BlockId),
    streamTimeout: Duration = DownloadStreamTimeout,
): Future[tuple[reached: bool, latestDownloadedId: Opt[BlockId]]] {.async: (raises: [CancelledError]).} =
  var
    latestDownloadedId = latestDownloadedId
    leaderKeyBytes: array[EdPublicKeySize, byte]
  debug "Sync download loop start", peer,
    targetBlock = sbyteutils.toHex(targetBlock)

  while true:
    if hasBlock(syncer.localTree, targetBlock):
      debug "Sync: target already local", peer, targetBlock = sbyteutils.toHex(targetBlock)
      return (true, latestDownloadedId)

    let conn = (await openDownloadStream(
      syncer, peer, targetBlock, latestDownloadedId, streamTimeout)).valueOr:
      debug "Sync: download request failed", peer, targetBlock = sbyteutils.toHex(targetBlock)
      return (false, latestDownloadedId)

    try:
      var
        progressed = false
        blocksRead = 0
        prevId: BlockId
      while true:
        let readFut = readCryptarchiaPrefixedInner(conn)
        if not await readFut.withTimeout(streamTimeout):
          debug "Sync: download stream read timed out",
            peer, blocksRead, timeout = streamTimeout
          return (false, latestDownloadedId)
        let
          blkOpt = parseDownloadFrame(peer, blocksRead, await readFut).valueOr:
            return (false, latestDownloadedId)
          blk = blkOpt.valueOr:
            if not progressed:
              debug "Sync: batch made no progress", peer, blocksRead
              return (false, latestDownloadedId)
            info "Sync: batch applied, continuing", peer, blocksApplied = blocksRead
            break
        template hdr: untyped = blk.header
        if blocksRead > 0 and hdr.parentBlock != prevId:
          debug "Sync: non-contiguous block stream",
            peer,
            parent = sbyteutils.toHex(hdr.parentBlock),
            expectedParent = sbyteutils.toHex(prevId)
          return (false, latestDownloadedId)
        let id = blockId(hdr)
        prevId = id
        inc blocksRead
        (await syncer.processor.addBlock(blk, id)).isOkOr:
          # Sync streams blocks in parent order, so even a recoverable error
          # means this peer's stream is unusable (unless already applied or in flight).
          case error.kind
          of BlockApplyErrorKind.AlreadyApplied, BlockApplyErrorKind.InFlight:
            debug "Sync: block already applied or in flight",
              peer, blockId = sbyteutils.toHex(id), kind = error.kind
            continue
          elif error.kind.isRecoverable:
            debug "Sync: block deferred, cancelling download",
              peer, blockId = sbyteutils.toHex(id), err = error.kind
            return (false, latestDownloadedId)
          else:
            warn "Sync: invalid block from peer, cancelling download",
              peer, blockId = sbyteutils.toHex(id), err = $error
            return (false, latestDownloadedId)
        doAssert toBytes(hdr.proofOfLeadership.leaderKey, leaderKeyBytes) == EdPublicKeySize
        info "Sync ingested block",
          peer,
          id = sbyteutils.toHex(id),
          bedrockVersion = hdr.bedrockVersion,
          parent = sbyteutils.toHex(hdr.parentBlock),
          slot = hdr.slot,
          bodyRoot = sbyteutils.toHex(hdr.bodyRoot),
          txCount = blk.txs.len,
          polLeaderVoucher = sbyteutils.toHex(hdr.proofOfLeadership.leaderVoucher),
          polEntropyContribution = sbyteutils.toHex(hdr.proofOfLeadership.entropyContribution),
          polProof = sbyteutils.toHex(hdr.proofOfLeadership.proof),
          polLeaderKey = sbyteutils.toHex(leaderKeyBytes),
          blockSignature = sbyteutils.toHex(blk.signature.data)
        progressed = true
        latestDownloadedId = Opt.some(id)
        if id == targetBlock:
          debug "Sync: target reached", peer, targetBlock = sbyteutils.toHex(targetBlock)
          return (true, latestDownloadedId)
    finally:
      await noCancel conn.close()

proc queryTrustedTipsOnce(
    syncer: Syncer,
    bootstrapPeerProvider: PeerProvider,
    tipTimeout: Duration,
): Future[seq[BlockId]] {.async: (raises: [CancelledError]).} =
  let peers = bootstrapPeerProvider()
  if peers.len == 0:
    return @[]
  let futs = peers.mapIt(sendGetTipRequest(syncer, it, tipTimeout))
  try:
    await allFutures(futs)
  except CancelledError as exc:
    await cancelAndWait(futs)
    raise exc

  var tips: seq[BlockId]
  for i, fut in futs:
    let
      peer = peers[i]
      resp = (await fut).valueOr:
        debug "IBD: GetTip failed", peer
        continue
    case resp.kind
    of gtrFailure:
      debug "IBD: GetTip returned failure", peer, reason = resp.failureMessage
    of gtrTip:
      let tip = resp.tipData.tip
      info "IBD: GetTip returned success",
        peer,
        targetBlock = sbyteutils.toHex(tip),
        height = resp.tipData.height,
        slot = resp.tipData.slot
      if tip notin tips:
        tips.add(tip)
  tips

proc queryTrustedTips(
    syncer: Syncer,
    bootstrapPeerProvider: PeerProvider,
    roundDelay: Duration,
    tipTimeout: Duration,
): Future[seq[BlockId]] {.async: (raises: [CancelledError]).} =
  for attempt in 0 .. MaxTipRetries:
    let tips = await queryTrustedTipsOnce(syncer, bootstrapPeerProvider, tipTimeout)
    if tips.len > 0 or attempt == MaxTipRetries:
      return tips
    let delay = roundDelay * (1 shl attempt)
    warn "IBD: no trusted peer provided a valid tip, retrying",
      retry = attempt + 1, maxRetries = MaxTipRetries, delay
    await sleepAsync(delay)

proc initialBlockDownload*(
    syncer: Syncer,
    bootstrapPeerProvider: PeerProvider,
    roundDelay: Duration = IbdRoundDelay,
    tipTimeout: Duration = GetTipTimeout,
    streamTimeout: Duration = DownloadStreamTimeout,
): Future[void] {.async: (raises: [IBDFailure, CancelledError]).} =
  if bootstrapPeerProvider == nil:
    debug "IBD skipped: no configured peers"
    return
  if syncer.peerProvider == nil:
    warn "IBD failed: no peer provider configured"
    raise newException(IBDFailure, "Initial block download failed: no peer provider configured")

  info "Starting initial block download", protocol = syncer.chainSyncProtocol

  while true:
    let tips = await queryTrustedTips(syncer, bootstrapPeerProvider, roundDelay, tipTimeout)
    if tips.len == 0:
      warn "IBD failed: no trusted peer provided a valid tip"
      raise newException(IBDFailure, "Initial block download failed: no trusted peer provided a valid tip")

    let unsyncedTips = tips.filterIt(not hasBlock(syncer.localTree, it))
    if unsyncedTips.len == 0:
      return

    for tip in unsyncedTips:
      var
        reached = false
        latestDownloadedId = Opt.none(BlockId)
      for peer in syncer.peerProvider():
        (reached, latestDownloadedId) =
          await downloadBlocks(syncer, peer, tip, latestDownloadedId, streamTimeout)
        if reached:
          info "IBD synced target tip", peer, targetBlock = sbyteutils.toHex(tip)
          break
        debug "IBD: peer sync failed", peer, targetBlock = sbyteutils.toHex(tip)

    await sleepAsync(roundDelay)

{.pop.}
