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
  libp2p/switch,
  stew/byteutils as sbyteutils,
  ./[framing, syncer_types, types]

from ../chain/local_tree import
  LocalTree, lcaBlockIdAndHeight, hasBlock, getBlock, blockHeight,
  localTip
from ../core/types import BlockId
from ../chain/block_validation import encode, header

logScope:
  topics = "cryptarchia_sync"

func getTipResponseFromLocalTree(localTree: LocalTree): GetTipResponse =
  GetTipResponse(
    kind: gtrTip,
    tipData: localTree.localTip(),
  )

func distinctKnownBlockIds(known: KnownBlocks): seq[BlockId] =
  var ids = newSeqOfCap[BlockId](2 + known.additionalBlocks.len)
  for id in [known.localTip, known.latestImmutableBlock]:
    if id != DefaultBlockId and id notin ids:
      ids.add id
  for id in known.additionalBlocks:
    if id != DefaultBlockId and id notin ids:
      ids.add id
  ids

func deepestKnownAncestor(
    localTree: LocalTree, target: BlockId, known: KnownBlocks,
): Opt[(BlockId, uint64)] =
  var
    ancestorId: BlockId
    ancestorHeight: uint64
    haveAncestor: bool
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
  let
    targetHeight = localTree.blockHeight(target).valueOr:
      return @[]
    (ancestorId, ancestorHeight) = deepestKnownAncestor(
      localTree, target, req.knownBlocks).valueOr:
      return @[]
  if ancestorId == target:
    return @[]
  let pathLen = int(targetHeight - ancestorHeight)
  if pathLen <= 0:
    return @[]
  let
    skip = if pathLen > maxBlocks: pathLen - maxBlocks else: 0
    sendCap = min(pathLen, maxBlocks)
  var
    sendIds = newSeqOfCap[BlockId](sendCap)
    skipped = 0
    curId = target
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
    conn: Connection, localTree: LocalTree, ibdInProgress: bool,
) {.async: (raises: [BincodeError, LPStreamError, CancelledError]).} =
  debug "Sync handler: GetTip request"
  let
    tipResp =
      if ibdInProgress:
        GetTipResponse(kind: gtrFailure, failureMessage: "initial block download in progress")
      else:
        getTipResponseFromLocalTree(localTree)
    respInner = try:
      encode(tipResp, cryptarchiaSyncBincodeConfig)
    except BincodeError:
      debug "Sync handler: GetTip serialize failed", exc = getCurrentExceptionMsg()
      return
  if respInner.len > 0:
    await writeCryptarchiaPrefixedInner(conn, respInner)
  if tipResp.kind == gtrTip:
    debug "Sync handler: GetTip response ok",
      tip = sbyteutils.toHex(tipResp.tipData.tip),
      height = tipResp.tipData.height

func failureResp(msg: string): DownloadBlocksResponse =
  DownloadBlocksResponse(
    kind: dbrFailure,
    blocksUnavailableReason: BlocksUnavailableReason(kind: burUnknown, message: msg),
  )

proc serveDownloadBlocksRequest(
    conn: Connection, localTree: LocalTree, req: DownloadBlocksRequest, ibdInProgress: bool,
) {.async: (raises: [BincodeError, LPStreamError, CancelledError]).} =
  proc writeResp(msg: DownloadBlocksResponse) {.async: (raises: [BincodeError, LPStreamError, CancelledError]).} =
    let innerBytes = try:
      encode(msg, cryptarchiaSyncBincodeConfig)
    except BincodeError:
      @[]
    if innerBytes.len > 0:
      await writeCryptarchiaPrefixedInner(conn, innerBytes)

  debug "Sync handler: download blocks request",
    targetBlock = sbyteutils.toHex(req.targetBlock)
  if ibdInProgress:
    await writeResp(failureResp("initial block download in progress"))
    return
  if req.knownBlocks.additionalBlocks.len > MaxKnownAdditionalBlocks:
    await writeResp(failureResp("too many additional known blocks"))
    return
  if not localTree.hasBlock(req.targetBlock):
    debug "Sync handler: target block not found",
      targetBlock = sbyteutils.toHex(req.targetBlock)
    await writeResp(DownloadBlocksResponse(
      kind: dbrFailure,
      blocksUnavailableReason: BlocksUnavailableReason(
        kind: burBlockNotFound, headerId: req.targetBlock)))
    debug "Sync handler: download failure response ok",
      targetBlock = sbyteutils.toHex(req.targetBlock)
    return
  let sendIds = cappedDownloadPathBlockIds(localTree, req)
  if sendIds.len == 0:
    debug "Sync handler: no blocks to send",
      targetBlock = sbyteutils.toHex(req.targetBlock)
    await writeResp(DownloadBlocksResponse(kind: dbrNoMoreBlocks))
    debug "Sync handler: download no-more-blocks response ok",
      targetBlock = sbyteutils.toHex(req.targetBlock)
    return
  debug "Sync handler: sending blocks",
    targetBlock = sbyteutils.toHex(req.targetBlock), count = sendIds.len
  var blocksSent = 0
  for i in countdown(sendIds.high, 0):
    let
      blk = localTree.getBlock(sendIds[i]).valueOr:
        debug "Sync handler: block load failed", blockId = sbyteutils.toHex(sendIds[i])
        await writeResp(DownloadBlocksResponse(
          kind: dbrFailure,
          blocksUnavailableReason: BlocksUnavailableReason(
            kind: burUnknown, message: "block load failed")))
        debug "Sync handler: download failure response ok",
          targetBlock = sbyteutils.toHex(req.targetBlock)
        return
      innerWire = try:
        encode(blk, cryptarchiaSyncBincodeConfig)
      except BincodeError:
        @[]
    if innerWire.len == 0:
      debug "Sync handler: block encode failed", blockId = sbyteutils.toHex(sendIds[i])
      await writeResp(DownloadBlocksResponse(
        kind: dbrFailure,
        blocksUnavailableReason: BlocksUnavailableReason(
          kind: burUnknown, message: "block encode failed")))
      debug "Sync handler: download failure response ok",
        targetBlock = sbyteutils.toHex(req.targetBlock)
      return
    await writeResp(DownloadBlocksResponse(kind: dbrBlock, downloadedBlock: innerWire))
    inc blocksSent
  await writeResp(DownloadBlocksResponse(kind: dbrNoMoreBlocks))
  debug "Sync handler: download blocks response ok",
    targetBlock = sbyteutils.toHex(req.targetBlock), blocksSent = blocksSent

proc dispatchCryptarchiaSyncRequest(
    syncer: Syncer, conn: Connection, inner: seq[byte],
) {.async: (raises: [BincodeError, LPStreamError, CancelledError]).} =
  let
    reqMsg = try:
      decode(inner, RequestMessage, cryptarchiaSyncBincodeConfig)
    except BincodeError:
      debug "Sync handler: request decode failed"
      return
    ibdInProgress = syncer.ibdFut != nil and not syncer.ibdFut.finished
  case reqMsg.kind
  of rmGetTip:
    await serveGetTipRequest(conn, syncer.localTree, ibdInProgress)
  of rmDownloadBlocksRequest:
    debug "Sync handler: download request decode ok",
      targetBlock = sbyteutils.toHex(reqMsg.downloadBlocksRequest.targetBlock)
    await serveDownloadBlocksRequest(
      conn, syncer.localTree, reqMsg.downloadBlocksRequest, ibdInProgress)

proc mountCryptarchiaSyncHandler*(syncer: Syncer) {.raises: [LPError].} =
  proc handle(conn: Connection, proto: string) {.async: (raises: [CancelledError]).} =
    defer:
      await noCancel conn.close()
    try:
      let inner = (await readCryptarchiaPrefixedInner(conn)).valueOr:
        debug "Sync handler: request read failed"
        return
      debug "Sync handler: request read ok", requestBytes = inner.len
      await dispatchCryptarchiaSyncRequest(syncer, conn, inner)
    except BincodeError as exc:
      debug "Sync handler error", exc = exc.msg
    except LPStreamError as exc:
      debug "Sync handler error", exc = exc.msg

  let lp = LPProtocol.new(codecs = @[syncer.chainSyncProtocol], handler = handle)
  lp.started = true
  syncer.sw.mount(lp)
  info "Syncer mounted chain-sync handler", protocol = syncer.chainSyncProtocol

{.pop.}
