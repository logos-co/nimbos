# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  std/[sequtils],
  bincode,
  chronicles,
  chronos,
  results,
  libp2p/[switch, peerid],
  libp2p/stream/connection,
  stew/byteutils as sbyteutils,
  ../chain/chain,
  ../core/block_validation,
  ./[framing, syncer_types, types]

from ../core/local_tree import
  LocalTree, localTipId, latestImmutableBlockId, hasBlock, addBlockToTree
from ../core/types import Block, BlockId, blockId, header
from libp2p/crypto/ed25519/ed25519 import EdPublicKeySize, toBytes

export types, chain, syncer_types

logScope:
  topics = "cryptarchia_ibd"

proc sendGetTipRequest*(
    syncer: Syncer,
    peer: PeerId,
): Future[Opt[GetTipResponse]] {.async: (raises: [CancelledError]).} =
  var wireReq: seq[byte]
  debug "IBD GetTip request", peer, protocol = syncer.chainSyncProtocol
  try:
    wireReq = serializeRequestMessageToSeq(
      RequestMessage(kind: rmGetTip), cryptarchiaSyncBincodeConfig)
    debug "IBD GetTip serialize ok", peer, requestBytes = wireReq.len
  except BincodeError, IOError:
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
      let resp = deserializeGetTipResponse(p, cryptarchiaSyncBincodeConfig)
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

const MaxKnownAdditionalBlocks = 5

func buildKnownBlocks*(
    localTree: LocalTree,
    additionalBlocks: openArray[BlockId] = [],
): KnownBlocks =
  let takeCount = min(additionalBlocks.len, MaxKnownAdditionalBlocks)
  KnownBlocks(
    localTip: localTipId(localTree),
    latestImmutableBlock: latestImmutableBlockId(localTree),
    additionalBlocks: (0 ..< takeCount).mapIt(additionalBlocks[it]),
  )

func decodeBlocksFromDownloadResponses*(messages: seq[DownloadBlocksResponse]): Opt[seq[Block]] =
  var blks = newSeqOfCap[Block](messages.len)
  for msg in messages:
    case msg.kind
    of dbrFailure:
      return Opt.none(seq[Block])
    of dbrNoMoreBlocks:
      discard
    of dbrBlock:
      let blkOpt = try:
        Opt.some(deserializeBlock(msg.downloadedBlock, cryptarchiaSyncBincodeConfig))
      except BincodeError:
        Opt.none(Block)
      let blk = blkOpt.valueOr:
        return Opt.none(seq[Block])
      blks.add blk
  Opt.some(blks)

proc sendDownloadBlocksRequest*(
    syncer: Syncer,
    peer: PeerId,
    request: DownloadBlocksRequest,
): Future[Opt[seq[Block]]] {.async: (raises: [CancelledError]).} =
  var wireReq: seq[byte]
  debug "IBD download blocks request",
    peer,
    targetBlock = sbyteutils.toHex(request.targetBlock),
    localTip = sbyteutils.toHex(request.knownBlocks.localTip),
    latestImmutable = sbyteutils.toHex(request.knownBlocks.latestImmutableBlock),
    additionalKnown = request.knownBlocks.additionalBlocks.len
  try:
    wireReq = serializeRequestMessageToSeq(
      RequestMessage(kind: rmDownloadBlocksRequest, downloadBlocksRequest: request),
      cryptarchiaSyncBincodeConfig,
    )
    debug "IBD download serialize ok", peer, requestBytes = wireReq.len
  except BincodeError, IOError:
    debug "IBD download serialize failed", peer, exc = getCurrentExceptionMsg()
    return Opt.none(seq[Block])
  var conn: Connection
  try:
    debug "IBD download dialing",
      peer,
      protocol = syncer.chainSyncProtocol,
      peerConnected = syncer.sw.isConnected(peer)
    conn = await syncer.sw.dial(peer, syncer.chainSyncProtocol)
    debug "IBD download dial ok", peer, protocol = conn.protocol
  except DialFailedError as exc:
    debug "IBD download dial failed", peer, exc = exc.msg, peerConnected = syncer.sw.isConnected(peer)
    return Opt.none(seq[Block])
  try:
    await writeCryptarchiaPrefixedInner(conn, wireReq)
    debug "IBD download write ok", peer, requestBytes = wireReq.len
    var blks = newSeqOfCap[Block](64)
    while true:
      let inner = (await readCryptarchiaPrefixedInner(conn)).valueOr:
        debug "IBD download response read failed", peer, blocks = blks.len
        return Opt.none(seq[Block])
      debug "IBD download read ok",
        peer,
        responseBytes = inner.len,
        blockIndex = blks.len
      let msgOpt = try:
        Opt.some(deserializeDownloadBlocksResponse(inner, cryptarchiaSyncBincodeConfig))
      except BincodeError as exc:
        debug "IBD download response deserialize failed", peer, exc = exc.msg
        Opt.none(DownloadBlocksResponse)
      let msg = msgOpt.valueOr:
        return Opt.none(seq[Block])
      case msg.kind
      of dbrFailure:
        debug "IBD download deserialize ok (failure)",
          peer,
          blocksUnavailableReason = msg.blocksUnavailableReason,
          blockIndex = blks.len
        return Opt.none(seq[Block])
      of dbrNoMoreBlocks:
        debug "IBD download deserialize ok (no more blocks)",
          peer, blocks = blks.len
        break
      of dbrBlock:
        let blkOpt = try:
          Opt.some(deserializeBlock(msg.downloadedBlock, cryptarchiaSyncBincodeConfig))
        except BincodeError as exc:
          debug "IBD download block decode failed", peer, exc = exc.msg
          Opt.none(Block)
        let blk = blkOpt.valueOr:
          return Opt.none(seq[Block])
        blks.add blk
        debug "IBD download deserialize ok (block)",
          peer, blockBytes = msg.downloadedBlock.len, blockIndex = blks.high
    debug "IBD download exchange complete", peer, blocks = blks.len
    Opt.some(blks)
  except BincodeError as exc:
    debug "IBD download exchange failed", peer, exc = exc.msg
    return Opt.none(seq[Block])
  except LPStreamError as exc:
    debug "IBD download exchange failed", peer, exc = exc.msg
    return Opt.none(seq[Block])
  finally:
    await noCancel conn.close()

proc onBlock(
    localTree: LocalTree,
    blk: Block,
    wallclock: SlotNumber,
) {.raises: [InvalidBlock].} =
  if not validateBlock(blk, localTree, wallclock):
    raise newException(InvalidBlock, "invalid block")
  discard addBlockToTree(localTree, blk)
  var leaderKeyBytes: array[EdPublicKeySize, byte]
  doAssert toBytes(header(blk).proofOfLeadership.leaderKey, leaderKeyBytes) == EdPublicKeySize
  info "IBD ingested block",
    id = sbyteutils.toHex(blockId(header(blk))),
    bedrockVersion = header(blk).bedrockVersion,
    parent = sbyteutils.toHex(header(blk).parentBlock),
    slot = header(blk).slot,
    blockRoot = sbyteutils.toHex(header(blk).blockRoot),
    txCount = blk.txs.len,
    polLeaderVoucher = sbyteutils.toHex(header(blk).proofOfLeadership.leaderVoucher),
    polEntropyContribution = sbyteutils.toHex(header(blk).proofOfLeadership.entropyContribution),
    polProof = sbyteutils.toHex(header(blk).proofOfLeadership.proof),
    polLeaderKey = sbyteutils.toHex(leaderKeyBytes),
    blockSignature = sbyteutils.toHex(blk.signature.data)

proc downloadBlocks(
    syncer: Syncer,
    peer: PeerId,
    targetBlock: Opt[BlockId] = Opt.none(BlockId),
): Future[bool] {.async: (raises: [CancelledError]).} =
  var latestDownloaded = Opt.none(Block)
  debug "IBD download loop start", peer,
    targetBlock = targetBlock
      .map(proc (id: BlockId): string = sbyteutils.toHex(id))
      .valueOr("unset")

  while true:
    let effectiveTarget =
      if targetBlock.isSome:
        targetBlock
      else:
        let tipOpt = await sendGetTipRequest(syncer, peer)
        if tipOpt.isNone:
          debug "IBD: GetTip failed", peer
          Opt.none(BlockId)
        else:
          case tipOpt.get.kind
          of gtrFailure:
            debug "IBD: GetTip returned failure", peer
            Opt.none(BlockId)
          of gtrTip:
            let tip = tipOpt.get.tipData.tip
            info "IBD: GetTip returned success", peer, targetBlock = sbyteutils.toHex(tip)
            Opt.some(tip)
    if effectiveTarget.isNone:
      debug "IBD: no effective target", peer
      return false
    if hasBlock(syncer.localTree, effectiveTarget.get):
      debug "IBD: target already local", peer, targetBlock = sbyteutils.toHex(effectiveTarget.get)
      return true

    let additionalKnown = latestDownloaded
      .map(proc (b: Block): seq[BlockId] = @[blockId(b.header)])
      .valueOr(@[])
    let downloadReq = DownloadBlocksRequest(
      targetBlock: effectiveTarget.get,
      knownBlocks: buildKnownBlocks(syncer.localTree, additionalKnown),
    )
    let blocks = (await sendDownloadBlocksRequest(
      syncer,
      peer,
      downloadReq,
    )).valueOr:
      debug "IBD: download request failed", peer, targetBlock = sbyteutils.toHex(effectiveTarget.get)
      return false

    debug "IBD: download response ok", peer, blocks = blocks.len, targetBlock = sbyteutils.toHex(downloadReq.targetBlock)
    if blocks.len == 0:
      debug "IBD: download returned no blocks", peer, targetBlock = sbyteutils.toHex(effectiveTarget.get)
      return false
    info "IBD: applying downloaded blocks", peer, count = blocks.len, targetBlock = sbyteutils.toHex(effectiveTarget.get)

    var targetReached = false
    for blk in blocks:
      latestDownloaded = Opt.some(blk)
      try:
        onBlock(syncer.localTree, blk, syncer.chain.currentWallclockSlot())
        debug "IBD: block ingest ok", peer, blockId = sbyteutils.toHex(blockId(blk.header))
        if blockId(blk.header) == effectiveTarget.get:
          targetReached = true
          break
      except InvalidBlock as exc:
        debug "IBD: block ingest failed", peer, exc = exc.msg
        return false

    if targetReached:
      debug "IBD: target reached", peer, targetBlock = sbyteutils.toHex(effectiveTarget.get)
      return true
    info "IBD: batch applied, continuing", peer, blocksApplied = blocks.len

proc initialBlockDownload*(
    syncer: Syncer,
    peers: seq[PeerId],
): Future[void] {.async: (raises: [IBDFailure, CancelledError]).} =
  if peers.len == 0:
    debug "IBD skipped: no peers"
    return
  info "Starting initial block download",
    peerCount = peers.len, protocol = syncer.chainSyncProtocol
  var numSuccess = 0
  for peer in peers:
    debug "IBD: syncing peer", peer
    if await downloadBlocks(syncer, peer, Opt.none(BlockId)):
      inc numSuccess
      info "IBD succeeded with peer", peer, successes = numSuccess
    else:
      debug "IBD: peer sync failed", peer

  if numSuccess == 0:
    warn "IBD failed: no peer synced successfully", peerCount = peers.len
    raise newException(IBDFailure, "Initial block download failed: no successful peer sync")

{.pop.}
