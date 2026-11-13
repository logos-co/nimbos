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
from ../core/types import Block, BlockId, blockId, header
from libp2p/crypto/ed25519/ed25519 import EdPublicKeySize, toBytes

export types, block_processor, syncer_types

logScope:
  topics = "cryptarchia_sync"

proc sendGetTipRequest*(
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

proc sendDownloadBlocksRequest*(
    syncer: Syncer,
    peer: PeerId,
    request: DownloadBlocksRequest,
): Future[Opt[seq[Block]]] {.async: (raises: [CancelledError]).} =
  var wireReq: seq[byte]
  debug "Sync download blocks request",
    peer,
    targetBlock = sbyteutils.toHex(request.targetBlock),
    localTip = sbyteutils.toHex(request.knownBlocks.localTip),
    latestImmutable = sbyteutils.toHex(request.knownBlocks.latestImmutableBlock),
    additionalKnown = request.knownBlocks.additionalBlocks.len
  try:
    wireReq = encode(
      RequestMessage(kind: rmDownloadBlocksRequest, downloadBlocksRequest: request),
      cryptarchiaSyncBincodeConfig,
    )
    debug "Sync download serialize ok", peer, requestBytes = wireReq.len
  except BincodeError:
    debug "Sync download serialize failed", peer, exc = getCurrentExceptionMsg()
    return Opt.none(seq[Block])
  var conn: Connection
  try:
    debug "Sync download dialing",
      peer,
      protocol = syncer.chainSyncProtocol,
      peerConnected = syncer.sw.isConnected(peer)
    conn = await syncer.sw.dial(peer, syncer.chainSyncProtocol)
    debug "Sync download dial ok", peer, protocol = conn.protocol
  except DialFailedError as exc:
    debug "Sync download dial failed", peer, exc = exc.msg, peerConnected = syncer.sw.isConnected(peer)
    return Opt.none(seq[Block])
  try:
    await writeCryptarchiaPrefixedInner(conn, wireReq)
    debug "Sync download write ok", peer, requestBytes = wireReq.len
    var blks = newSeqOfCap[Block](64)
    while true:
      let inner = (await readCryptarchiaPrefixedInner(conn)).valueOr:
        debug "Sync download response read failed", peer, blocks = blks.len
        return Opt.none(seq[Block])
      debug "Sync download read ok",
        peer,
        responseBytes = inner.len,
        blockIndex = blks.len
      let
        msgOpt = try:
          Opt.some(decode(inner, DownloadBlocksResponse, cryptarchiaSyncBincodeConfig))
        except BincodeError as exc:
          debug "Sync download response deserialize failed", peer, exc = exc.msg
          Opt.none(DownloadBlocksResponse)
        msg = msgOpt.valueOr:
          return Opt.none(seq[Block])
      case msg.kind
      of dbrFailure:
        debug "Sync download deserialize ok (failure)",
          peer,
          blocksUnavailableReason = msg.blocksUnavailableReason,
          blockIndex = blks.len
        return Opt.none(seq[Block])
      of dbrNoMoreBlocks:
        debug "Sync download deserialize ok (no more blocks)",
          peer, blocks = blks.len
        break
      of dbrBlock:
        let blk = decodeSyncBlock(msg.downloadedBlock).valueOr:
          debug "Sync download block decode failed", peer, reason = error
          return Opt.none(seq[Block])
        blks.add blk
        debug "Sync download deserialize ok (block)",
          peer, blockBytes = msg.downloadedBlock.len, blockIndex = blks.high
    debug "Sync download exchange complete", peer, blocks = blks.len
    Opt.some(blks)
  except BincodeError as exc:
    debug "Sync download exchange failed", peer, exc = exc.msg
    return Opt.none(seq[Block])
  except LPStreamError as exc:
    debug "Sync download exchange failed", peer, exc = exc.msg
    return Opt.none(seq[Block])
  finally:
    await noCancel conn.close()

proc onBlock(
    syncer: Syncer, blk: Block, id: BlockId
): Future[Result[void, BlockApplyError]] {.async: (raises: [CancelledError]).} =
  let res = await syncer.processor.addBlock(blk, id)
  res.isOkOr:
    return res
  var leaderKeyBytes: array[EdPublicKeySize, byte]
  doAssert toBytes(header(blk).proofOfLeadership.leaderKey, leaderKeyBytes) == EdPublicKeySize
  info "Sync ingested block",
    id = sbyteutils.toHex(id),
    bedrockVersion = header(blk).bedrockVersion,
    parent = sbyteutils.toHex(header(blk).parentBlock),
    slot = header(blk).slot,
    bodyRoot = sbyteutils.toHex(header(blk).bodyRoot),
    txCount = blk.txs.len,
    polLeaderVoucher = sbyteutils.toHex(header(blk).proofOfLeadership.leaderVoucher),
    polEntropyContribution = sbyteutils.toHex(header(blk).proofOfLeadership.entropyContribution),
    polProof = sbyteutils.toHex(header(blk).proofOfLeadership.proof),
    polLeaderKey = sbyteutils.toHex(leaderKeyBytes),
    blockSignature = sbyteutils.toHex(blk.signature.data)
  res

proc downloadBlocks*(
    syncer: Syncer,
    peer: PeerId,
    targetBlock: BlockId,
    latestDownloadedId = Opt.none(BlockId),
): Future[(bool, Opt[BlockId])] {.async: (raises: [CancelledError]).} =
  var latestDownloadedId = latestDownloadedId
  debug "Sync download loop start", peer,
    targetBlock = sbyteutils.toHex(targetBlock)

  while true:
    if hasBlock(syncer.localTree, targetBlock):
      debug "Sync: target already local", peer, targetBlock = sbyteutils.toHex(targetBlock)
      return (true, latestDownloadedId)

    let
      additionalKnown = latestDownloadedId
        .map(proc (id: BlockId): seq[BlockId] = @[id])
        .valueOr(@[])
      downloadReq = DownloadBlocksRequest(
        targetBlock: targetBlock,
        knownBlocks: buildKnownBlocks(syncer.localTree, additionalKnown),
      )
      blocks = (await sendDownloadBlocksRequest(
        syncer,
        peer,
        downloadReq,
      )).valueOr:
        debug "Sync: download request failed", peer, targetBlock = sbyteutils.toHex(targetBlock)
        return (false, latestDownloadedId)

    debug "Sync: download response ok", peer, blocks = blocks.len, targetBlock = sbyteutils.toHex(downloadReq.targetBlock)
    if blocks.len == 0:
      debug "Sync: download returned no blocks", peer, targetBlock = sbyteutils.toHex(targetBlock)
      return (false, latestDownloadedId)
    info "Sync: applying downloaded blocks", peer, count = blocks.len, targetBlock = sbyteutils.toHex(targetBlock)

    var
      targetReached = false
      progressed = false
    for blk in blocks:
      let id = blockId(blk.header)
      (await onBlock(syncer, blk, id)).isOkOr:
        # Sync streams blocks in parent order, so even a recoverable error
        # means this peer's stream is unusable (unless already applied or in flight).
        case error.kind
        of BlockApplyErrorKind.AlreadyApplied:
          debug "Sync: block already applied",
            peer, blockId = sbyteutils.toHex(id)
        of BlockApplyErrorKind.InFlight:
          debug "Sync: block already in flight",
            peer, blockId = sbyteutils.toHex(id)
          continue
        elif error.kind.isRecoverable:
          debug "Sync: block deferred, cancelling download",
            peer, blockId = sbyteutils.toHex(id), err = error.kind
          return (false, latestDownloadedId)
        else:
          warn "Sync: invalid block from peer, cancelling download",
            peer, blockId = sbyteutils.toHex(id), err = $error
          return (false, latestDownloadedId)
        latestDownloadedId = Opt.some(id)
        if id == targetBlock:
          targetReached = true
          break
        continue
      latestDownloadedId = Opt.some(id)
      progressed = true
      debug "Sync: block ingest ok", peer, blockId = sbyteutils.toHex(id)
      if id == targetBlock:
        targetReached = true
        break

    if targetReached:
      debug "Sync: target reached", peer, targetBlock = sbyteutils.toHex(targetBlock)
      return (true, latestDownloadedId)
    if not progressed:
      debug "Sync: peer provided blocks but none were new", peer
      return (false, latestDownloadedId)
    info "Sync: batch applied, continuing", peer, blocksApplied = blocks.len

const IbdRoundDelay = 1.seconds
  ## Delay between rounds of Initial Block Download (`T_round` in spec).

proc queryTrustedTips(
    syncer: Syncer,
    bootstrapPeerProvider: PeerProvider,
): Future[seq[BlockId]] {.async: (raises: [CancelledError]).} =
  let
    peers = bootstrapPeerProvider()
    futs = peers.mapIt(sendGetTipRequest(syncer, it))
  try:
    await allFutures(futs)
  except CancelledError as exc:
    for fut in futs:
      fut.cancelSoon()
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

proc initialBlockDownload*(
    syncer: Syncer,
    bootstrapPeerProvider: PeerProvider,
    roundDelay: Duration = IbdRoundDelay,
): Future[void] {.async: (raises: [IBDFailure, CancelledError]).} =
  if bootstrapPeerProvider == nil:
    debug "IBD skipped: no configured peers"
    return

  info "Starting initial block download", protocol = syncer.chainSyncProtocol
  let dbrPeerProvider =
    if syncer.peerProvider != nil: syncer.peerProvider
    else: bootstrapPeerProvider

  while true:
    let tips = await queryTrustedTips(syncer, bootstrapPeerProvider)
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
      for peer in dbrPeerProvider():
        (reached, latestDownloadedId) =
          await downloadBlocks(syncer, peer, tip, latestDownloadedId)
        if reached:
          info "IBD synced target tip", peer, targetBlock = sbyteutils.toHex(tip)
          break
        debug "IBD: peer sync failed", peer, targetBlock = sbyteutils.toHex(tip)

    await sleepAsync(roundDelay)

{.pop.}
