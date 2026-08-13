# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  bincode,
  chronicles,
  chronos,
  results,
  libp2p/[switch, errors],
  libp2p/protocols/protocol,
  libp2p/stream/connection,
  stew/byteutils as sbyteutils,
  ./[framing, syncer_types, types]

from ../core/local_tree import
  LocalTree, localTipId, lcaBlockIdAndHeight, hasBlock, getBlock, blockHeight
from ../core/types import Block, BlockId
from ../core/mantle/primitives import SlotNumber

logScope:
  topics = "cryptarchia_ibd"

func getTipResponseFromLocalTree(localTree: LocalTree): GetTipResponse =
  let tipId = localTree.localTipId()
  let height = localTree.blockHeight(tipId).valueOr(0'u64)
  let blk = localTree.getBlock(tipId).valueOr(default(Block))
  GetTipResponse(
    kind: gtrTip,
    tipData: Tip(
      tip: tipId,
      slot: blk.header.slot,
      height: height,
    ),
  )

func distinctKnownBlockIds(known: KnownBlocks): seq[BlockId] =
  const defaultBlockId = default(BlockId)
  var ids = newSeqOfCap[BlockId](2 + known.additionalBlocks.len)
  for id in [known.localTip, known.latestImmutableBlock]:
    if id != defaultBlockId and id notin ids:
      ids.add id
  for id in known.additionalBlocks:
    if id != defaultBlockId and id notin ids:
      ids.add id
  ids

func deepestKnownAncestor(
    localTree: LocalTree, target: BlockId, known: KnownBlocks,
): Opt[(BlockId, uint64)] =
  var ancestorId: BlockId
  var ancestorHeight: uint64
  var haveAncestor: bool
  for kid in distinctKnownBlockIds(known):
    if not localTree.hasBlock(kid):
      continue
    let (candidateId, candidateHeight) = lcaBlockIdAndHeight(localTree, kid, target).valueOr:
      continue
    if not haveAncestor or candidateHeight > ancestorHeight:
      ancestorHeight = candidateHeight
      ancestorId = candidateId
      haveAncestor = true
  if not haveAncestor:
    Opt.none((BlockId, uint64))
  else:
    Opt.some((ancestorId, ancestorHeight))

func cappedDownloadPathBlockIds*(
    localTree: LocalTree, req: DownloadBlocksRequest,
    maxBlocks: int = MaxRequestBlocks,
): seq[BlockId] =
  let target = req.targetBlock
  if not localTree.hasBlock(target):
    return @[]
  let targetHeight = localTree.blockHeight(target).valueOr:
    return @[]
  let (ancestorId, ancestorHeight) = deepestKnownAncestor(
    localTree, target, req.knownBlocks).valueOr:
    return @[]
  if ancestorId == target:
    return @[]
  let pathLen = int(targetHeight - ancestorHeight)
  if pathLen <= 0:
    return @[]
  let skip = if pathLen > maxBlocks: pathLen - maxBlocks else: 0
  let sendCap = min(pathLen, maxBlocks)
  var sendIds = newSeqOfCap[BlockId](sendCap)
  var skipped = 0
  var curId = target
  while curId != ancestorId and sendIds.len < sendCap:
    if skipped < skip:
      inc skipped
    else:
      sendIds.add curId
    let blk = localTree.getBlock(curId).valueOr:
      return @[]
    curId = blk.header.parentBlock
  sendIds

proc serveGetTipRequest(
    conn: Connection, localTree: LocalTree,
) {.async: (raises: [BincodeError, LPStreamError, CancelledError]).} =
  debug "IBD handler: GetTip request"
  let tipResp = getTipResponseFromLocalTree(localTree)
  let respInner = try:
    serializeGetTipResponseToSeq(tipResp, cryptarchiaSyncBincodeConfig)
  except BincodeError, IOError:
    debug "IBD handler: GetTip serialize failed", exc = getCurrentExceptionMsg()
    return
  if respInner.len > 0:
    await writeCryptarchiaPrefixedInner(conn, respInner)
  debug "IBD handler: GetTip response ok",
    tip = sbyteutils.toHex(tipResp.tipData.tip),
    height = tipResp.tipData.height

proc serveDownloadBlocksRequest(
    conn: Connection, localTree: LocalTree, req: DownloadBlocksRequest,
) {.async: (raises: [BincodeError, LPStreamError, CancelledError]).} =
  proc writeResp(msg: DownloadBlocksResponse) {.async: (raises: [BincodeError, LPStreamError, CancelledError]).} =
    let innerBytes = try:
      serializeDownloadBlocksResponseToSeq(msg, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      @[]
    if innerBytes.len > 0:
      await writeCryptarchiaPrefixedInner(conn, innerBytes)

  debug "IBD handler: download blocks request",
    targetBlock = sbyteutils.toHex(req.targetBlock)
  if not localTree.hasBlock(req.targetBlock):
    debug "IBD handler: target block not found",
      targetBlock = sbyteutils.toHex(req.targetBlock)
    await writeResp(DownloadBlocksResponse(
      kind: dbrFailure,
      blocksUnavailableReason: BlocksUnavailableReason(
        kind: burBlockNotFound, headerId: req.targetBlock)))
    debug "IBD handler: download failure response ok",
      targetBlock = sbyteutils.toHex(req.targetBlock)
    return
  let sendIds = cappedDownloadPathBlockIds(localTree, req)
  if sendIds.len == 0:
    debug "IBD handler: no blocks to send",
      targetBlock = sbyteutils.toHex(req.targetBlock)
    await writeResp(DownloadBlocksResponse(kind: dbrNoMoreBlocks))
    debug "IBD handler: download no-more-blocks response ok",
      targetBlock = sbyteutils.toHex(req.targetBlock)
    return
  debug "IBD handler: sending blocks",
    targetBlock = sbyteutils.toHex(req.targetBlock), count = sendIds.len
  var blocksSent = 0
  for i in countdown(sendIds.high, 0):
    let blk = localTree.getBlock(sendIds[i]).valueOr:
      debug "IBD handler: block load failed", blockId = sbyteutils.toHex(sendIds[i])
      await writeResp(DownloadBlocksResponse(
        kind: dbrFailure,
        blocksUnavailableReason: BlocksUnavailableReason(
          kind: burUnknown, message: "block load failed")))
      debug "IBD handler: download failure response ok",
        targetBlock = sbyteutils.toHex(req.targetBlock)
      return
    let innerWire = try:
      serializeBlockToSeq(blk, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      @[]
    if innerWire.len == 0:
      debug "IBD handler: block encode failed", blockId = sbyteutils.toHex(sendIds[i])
      await writeResp(DownloadBlocksResponse(
        kind: dbrFailure,
        blocksUnavailableReason: BlocksUnavailableReason(
          kind: burUnknown, message: "block encode failed")))
      debug "IBD handler: download failure response ok",
        targetBlock = sbyteutils.toHex(req.targetBlock)
      return
    await writeResp(DownloadBlocksResponse(kind: dbrBlock, downloadedBlock: innerWire))
    inc blocksSent
  await writeResp(DownloadBlocksResponse(kind: dbrNoMoreBlocks))
  debug "IBD handler: download blocks response ok",
    targetBlock = sbyteutils.toHex(req.targetBlock), blocksSent = blocksSent

proc dispatchCryptarchiaSyncRequest(
    syncer: Syncer, conn: Connection, inner: seq[byte],
) {.async: (raises: [BincodeError, LPStreamError, CancelledError]).} =
  let reqMsg = try:
    deserializeRequestMessage(inner, cryptarchiaSyncBincodeConfig)
  except BincodeError:
    debug "IBD handler: request decode failed"
    return
  case reqMsg.kind
  of rmGetTip:
    await serveGetTipRequest(conn, syncer.localTree)
  of rmDownloadBlocksRequest:
    debug "IBD handler: download request decode ok",
      targetBlock = sbyteutils.toHex(reqMsg.downloadBlocksRequest.targetBlock)
    await serveDownloadBlocksRequest(
      conn, syncer.localTree, reqMsg.downloadBlocksRequest)

proc mountCryptarchiaSyncHandler*(syncer: Syncer) {.raises: [LPError].} =
  proc handle(conn: Connection, proto: string) {.async: (raises: [CancelledError]).} =
    defer:
      await noCancel conn.close()
    try:
      let inner = (await readCryptarchiaPrefixedInner(conn)).valueOr:
        debug "IBD handler: request read failed"
        return
      debug "IBD handler: request read ok", requestBytes = inner.len
      await dispatchCryptarchiaSyncRequest(syncer, conn, inner)
    except BincodeError as exc:
      debug "IBD handler error", exc = exc.msg
    except LPStreamError as exc:
      debug "IBD handler error", exc = exc.msg

  let lp = LPProtocol.new(codecs = @[syncer.chainSyncProtocol], handler = handle)
  lp.started = true
  syncer.sw.mount(lp)
  info "Syncer mounted chain-sync handler", protocol = syncer.chainSyncProtocol

{.pop.}
