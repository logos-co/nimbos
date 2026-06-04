# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  std/[options, sequtils, sets],
  chronicles,
  chronos,
  libp2p/[switch, peerid, errors],
  libp2p/protocols/protocol,
  libp2p/stream/connection,
  stew/endians2,
  stew/byteutils as sbyteutils

import ../core/local_tree
import "../core/block_validation"
import ./config
import ./types

from "../core/types" import Block, BlockId, blockId
from ../core/mantle/primitives import SlotNumber
from libp2p/crypto/ed25519/ed25519 import EdPublicKeySize, toBytes

export types

logScope:
  topics = "cryptarchia_ibd"

# ---------------------------------------------------------------------------
# Wire framing (u32 inner length inside libp2p writeLp / readLp)
# ---------------------------------------------------------------------------

proc readCryptarchiaPrefixedInner*(conn: Connection): Future[Option[seq[byte]]] {.async.} =
  ## One libp2p LP frame: read varint frame length, then LE ``uint32`` inner length, then
  ## exactly ``innerLen`` bytes.
  try:
    let lpBodyLen = await conn.readVarint()
    if lpBodyLen < uint64(CryptarchiaSyncInnerLengthPrefixSize):
      return none(seq[byte])
    var lenPrefix = newSeqUninit[byte](CryptarchiaSyncInnerLengthPrefixSize)
    await conn.readExactly(addr lenPrefix[0], CryptarchiaSyncInnerLengthPrefixSize)
    let innerLen = int(uint32.fromBytesLE(lenPrefix.toOpenArray(
        0, CryptarchiaSyncInnerLengthPrefixSize - 1)))
    if uint64(CryptarchiaSyncInnerLengthPrefixSize + innerLen) != lpBodyLen:
      return none(seq[byte])
    if innerLen == 0:
      return some(newSeq[byte]())
    var inner = newSeqUninit[byte](innerLen)
    await conn.readExactly(addr inner[0], innerLen)
    some(inner)
  except CatchableError as exc:
    debug "IBD wire read failed", exc = exc.msg
    none(seq[byte])

proc writeCryptarchiaPrefixedInner*(conn: Connection, inner: seq[byte]) {.async.} =
  ## Prepend LE ``uint32`` inner length, then ``writeLp``.
  let framed = addPrefixLengthToPayload(inner)
  await conn.writeLp(framed)

func parseRequestMessageKind*(inner: openArray[byte]): Option[RequestMessageKind] {.raises: [].} =
  ## First 4 bytes of the inner bincode body are ``RequestMessageKind`` (u32 LE).
  const kindWireSize = sizeof(uint32)
  if inner.len < kindWireSize:
    return none(RequestMessageKind)
  let w = uint32.fromBytesLE(inner.toOpenArray(0, kindWireSize - 1))
  if w > uint32(ord(high(RequestMessageKind))):
    return none(RequestMessageKind)
  some(RequestMessageKind(w))

# ---------------------------------------------------------------------------
# GetTip
# ---------------------------------------------------------------------------

proc getTipResponseFromLocalTree*(localTree: LocalTree): GetTipResponse {.raises: [].} =
  GetTipResponse(
    kind: gtrTip,
    tipData: Tip(
      tip: localTipId(localTree),
      slot: SlotNumber(0),
      height: localTree.latestImmutableHeight,
    ),
  )

proc sendGetTipRequest*(
    sw: Switch,
    peer: PeerId,
    chainSyncProtocol: string,
): Future[Option[GetTipResponse]] {.async.} =
  var wireReq: seq[byte]
  debug "IBD GetTip request", peer, protocol = chainSyncProtocol
  try:
    wireReq = serializeRequestMessageToSeq(
      RequestMessage(kind: rmGetTip), cryptarchiaSyncBincodeConfig)
  except CatchableError as exc:
    debug "IBD GetTip serialize failed", peer, exc = exc.msg
    return none(GetTipResponse)
  var conn: Connection
  try:
    conn = await sw.dial(peer, chainSyncProtocol)
  except CatchableError as exc:
    debug "IBD GetTip dial failed", peer, exc = exc.msg
    return none(GetTipResponse)
  try:
    await writeCryptarchiaPrefixedInner(conn, wireReq)
    let payloadOpt = await readCryptarchiaPrefixedInner(conn)
    if payloadOpt.isNone:
      debug "IBD GetTip response read failed", peer
      return none(GetTipResponse)
    let p = payloadOpt.get
    try:
      let resp = deserializeGetTipResponse(p, cryptarchiaSyncBincodeConfig)
      case resp.kind
      of gtrTip:
        debug "IBD GetTip response",
          peer,
          tip = resp.tipData.tip,
          height = resp.tipData.height
      of gtrFailure:
        debug "IBD GetTip peer failure", peer, reason = resp.failureMessage
      return some(resp)
    except CatchableError as exc:
      debug "IBD GetTip deserialize failed", peer, exc = exc.msg
      return none(GetTipResponse)
  except CatchableError as exc:
    debug "IBD GetTip exchange failed", peer, exc = exc.msg
    return none(GetTipResponse)
  finally:
    try:
      await conn.close()
    except CatchableError:
      discard

# ---------------------------------------------------------------------------
# Download blocks
# ---------------------------------------------------------------------------

proc buildKnownBlocks*(
    localTree: LocalTree,
    additionalBlocks: openArray[BlockId] = [],
): KnownBlocks =
  let takeCount = min(additionalBlocks.len, MaxKnownAdditionalBlocks)
  var extras = newSeqOfCap[BlockId](takeCount)
  for i in 0 ..< takeCount:
    extras.add(additionalBlocks[i])
  KnownBlocks(
    localTip: localTipId(localTree),
    latestImmutableBlock: latestImmutableBlockId(localTree),
    additionalBlocks: extras,
  )

func decodeBlocksFromDownloadResponses*(messages: seq[DownloadBlocksResponse]): Option[seq[Block]] {.raises: [].} =
  var blks = newSeqOfCap[Block](messages.len)
  for msg in messages:
    case msg.kind
    of dbrFailure:
      return none(seq[Block])
    of dbrNoMoreBlocks:
      discard
    of dbrBlock:
      let blkOpt = try:
        some(deserializeBlock(msg.downloadedBlock, cryptarchiaSyncBincodeConfig))
      except CatchableError:
        none(Block)
      if blkOpt.isNone:
        return none(seq[Block])
      blks.add blkOpt.get
  some(blks)

proc sendDownloadBlocksRequest*(
    sw: Switch,
    peer: PeerId,
    request: DownloadBlocksRequest,
    chainSyncProtocol: string,
): Future[Option[seq[DownloadBlocksResponse]]] {.async.} =
  var wireReq: seq[byte]
  debug "IBD download blocks request",
    peer,
    targetBlock = request.targetBlock,
    localTip = request.knownBlocks.localTip,
    latestImmutable = request.knownBlocks.latestImmutableBlock,
    additionalKnown = request.knownBlocks.additionalBlocks.len
  try:
    wireReq = serializeRequestMessageToSeq(
      RequestMessage(kind: rmDownloadBlocksRequest, downloadBlocksRequest: request),
      cryptarchiaSyncBincodeConfig,
    )
  except CatchableError as exc:
    debug "IBD download serialize failed", peer, exc = exc.msg
    return none(seq[DownloadBlocksResponse])
  var conn: Connection
  try:
    conn = await sw.dial(peer, chainSyncProtocol)
  except CatchableError as exc:
    debug "IBD download dial failed", peer, exc = exc.msg
    return none(seq[DownloadBlocksResponse])
  try:
    await writeCryptarchiaPrefixedInner(conn, wireReq)
    var acc = newSeqOfCap[DownloadBlocksResponse](64)
    while true:
      let innerOpt = await readCryptarchiaPrefixedInner(conn)
      if innerOpt.isNone:
        debug "IBD download response read failed", peer, messages = acc.len
        return none(seq[DownloadBlocksResponse])
      let msgOpt = try:
        some(deserializeDownloadBlocksResponse(innerOpt.get, cryptarchiaSyncBincodeConfig))
      except CatchableError as exc:
        debug "IBD download response deserialize failed", peer, exc = exc.msg
        none(DownloadBlocksResponse)
      if msgOpt.isNone:
        return none(seq[DownloadBlocksResponse])
      let msg = msgOpt.get
      acc.add msg
      case msg.kind
      of dbrFailure:
        debug "IBD download response: failure", peer, reason = msg.failureReason
        break
      of dbrNoMoreBlocks:
        debug "IBD download response: no more blocks", peer, messages = acc.len
        break
      of dbrBlock:
        debug "IBD download response: block", peer, blockBytes = msg.downloadedBlock.len
    debug "IBD download exchange complete", peer, messages = acc.len
    some(acc)
  except CatchableError as exc:
    debug "IBD download exchange failed", peer, exc = exc.msg
    return none(seq[DownloadBlocksResponse])
  finally:
    try:
      await conn.close()
    except CatchableError:
      discard

# ---------------------------------------------------------------------------
# IBD: path selection for download responses
# ---------------------------------------------------------------------------

func collectBlocksForDownloadRequest*(
    localTree: LocalTree,
    req: DownloadBlocksRequest,
): seq[Block] {.raises: [].} =
  let target = req.targetBlock
  if not localTree.hasBlock(target):
    return @[]
  var knownIds = initHashSet[BlockId](2 + req.knownBlocks.additionalBlocks.len)
  knownIds.incl req.knownBlocks.localTip
  knownIds.incl req.knownBlocks.latestImmutableBlock
  for id in req.knownBlocks.additionalBlocks:
    knownIds.incl id
  var bestLca = default(BlockId)
  var bestHeight: uint64 = 0
  var haveBest = false
  for kid in knownIds:
    if not localTree.hasBlock(kid):
      continue
    let lcaOpt = lcaBlockId(localTree, kid, target)
    if lcaOpt.isNone:
      continue
    let lca = lcaOpt.get
    let hOpt = localTree.blockHeight(lca)
    if hOpt.isNone:
      continue
    let h = hOpt.get
    if not haveBest or h > bestHeight:
      bestHeight = h
      bestLca = lca
      haveBest = true
  if not haveBest:
    return @[]
  if bestLca == target:
    return @[]
  var rev = newSeqOfCap[Block](8)
  var curId = target
  while curId != bestLca:
    let blkOpt = localTree.getBlock(curId)
    if blkOpt.isNone:
      return @[]
    let blk = blkOpt.get
    rev.add blk
    curId = blk.header.parentBlock
    if curId == default(BlockId):
      return @[]
  var forward = newSeqOfCap[Block](rev.len)
  for i in countdown(rev.high, 0):
    forward.add rev[i]
  forward

template awaitWriteDlRespLp(conn: Connection, msg: DownloadBlocksResponse) =
  ## u32-prefixed inner + ``writeLp``; skips write when encoding yields empty.
  block:
    let innerBytes = try:
      serializeDownloadBlocksResponseToSeq(msg, cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    if innerBytes.len > 0:
      await writeCryptarchiaPrefixedInner(conn, innerBytes)

# ---------------------------------------------------------------------------
# Sync stream mount (GetTip + download blocks)
# ---------------------------------------------------------------------------

proc mountCryptarchiaSyncHandler*(
    sw: Switch,
    localTree: LocalTree,
    chainSyncProtocol: string,
) {.raises: [LPError].} =
  proc handle(conn: Connection, proto: string) {.async: (raises: [CancelledError]).} =
    defer:
      try:
        await conn.close()
      except CatchableError:
        discard
    try:
      let innerOpt = await readCryptarchiaPrefixedInner(conn)
      if innerOpt.isNone:
        return
      let inner = innerOpt.get
      let kindOpt = parseRequestMessageKind(inner)
      if kindOpt.isNone:
        debug "IBD handler: invalid request kind"
        return
      case kindOpt.get
      of rmGetTip:
        debug "IBD handler: GetTip request"
        let respInner = try:
          serializeGetTipResponseToSeq(getTipResponseFromLocalTree(localTree), cryptarchiaSyncBincodeConfig)
        except CatchableError as exc:
          debug "IBD handler: GetTip serialize failed", exc = exc.msg
          @[]
        if respInner.len > 0:
          await writeCryptarchiaPrefixedInner(conn, respInner)
      of rmDownloadBlocksRequest:
        debug "IBD handler: download blocks request"
        let reqMsgOpt = try:
          some(deserializeRequestMessage(inner, cryptarchiaSyncBincodeConfig))
        except CatchableError:
          none(RequestMessage)
        if reqMsgOpt.isNone or reqMsgOpt.get.kind != rmDownloadBlocksRequest:
          debug "IBD handler: download request decode failed"
          return
        let req = reqMsgOpt.get.downloadBlocksRequest
        if not localTree.hasBlock(req.targetBlock):
          debug "IBD handler: target block not found", targetBlock = req.targetBlock
          awaitWriteDlRespLp(conn, DownloadBlocksResponse(
            kind: dbrFailure,
            failureReason: BlocksUnavailableReason(kind: burBlockNotFound, blockNotFoundId: req.targetBlock)))
        else:
          let blocks = collectBlocksForDownloadRequest(localTree, req)
          if blocks.len == 0:
            debug "IBD handler: no blocks to send", targetBlock = req.targetBlock
            awaitWriteDlRespLp(conn, DownloadBlocksResponse(kind: dbrNoMoreBlocks))
          else:
            debug "IBD handler: sending blocks", targetBlock = req.targetBlock, count = blocks.len
            for blk in blocks:
              let innerWire = try:
                serializeBlockToSeq(blk, cryptarchiaSyncBincodeConfig)
              except CatchableError:
                @[]
              if innerWire.len == 0 or innerWire.len > MaxBlockSize:
                debug "IBD handler: block encode failed or too large", blockBytes = innerWire.len
                awaitWriteDlRespLp(conn, DownloadBlocksResponse(
                  kind: dbrFailure,
                  failureReason: BlocksUnavailableReason(kind: burUnknown, unknownMessage: "")))
                return
              awaitWriteDlRespLp(conn, DownloadBlocksResponse(kind: dbrBlock, downloadedBlock: innerWire))
            awaitWriteDlRespLp(conn, DownloadBlocksResponse(kind: dbrNoMoreBlocks))
    except CatchableError as exc:
      debug "IBD handler error", exc = exc.msg

  let lp = LPProtocol.new(codecs = @[chainSyncProtocol], handler = handle)
  sw.mount(lp)
  info "Mounted cryptarchia chain-sync handler", protocol = chainSyncProtocol

# ---------------------------------------------------------------------------
# Block ingest
# ---------------------------------------------------------------------------

proc onBlock*(
    localTree: LocalTree,
    blk: Block,
) {.raises: [InvalidBlock].} =
  if not validateBlockHeader(blk, localTree) or not validateBlockBody(blk):
    raise newException(InvalidBlock, "invalid block")
  discard addBlockToTree(localTree, blk)
  let h = blk.header
  var leaderKeyBytes: array[EdPublicKeySize, byte]
  doAssert toBytes(h.proofOfLeadership.leaderKey, leaderKeyBytes) == EdPublicKeySize
  info "IBD ingested block",
    id = sbyteutils.toHex(blockId(h)),
    bedrockVersion = h.bedrockVersion,
    parent = sbyteutils.toHex(h.parentBlock),
    slot = h.slot,
    blockRoot = sbyteutils.toHex(h.blockRoot),
    txCount = blk.txs.len,
    polLeaderVoucher = sbyteutils.toHex(h.proofOfLeadership.leaderVoucher),
    polEntropyContribution = sbyteutils.toHex(h.proofOfLeadership.entropyContribution),
    polProof = sbyteutils.toHex(h.proofOfLeadership.proof),
    polLeaderKey = sbyteutils.toHex(leaderKeyBytes)

# ---------------------------------------------------------------------------
# IBD: requester loop
# ---------------------------------------------------------------------------

proc downloadBlocks*(
    sw: Switch,
    localTree: LocalTree,
    peer: PeerId,
    forkChoice: ForkChoice,
    chainSyncProtocol: string,
    targetBlock: Option[BlockId] = none(BlockId),
): Future[bool] {.async.} =
  discard forkChoice
  var latestDownloaded = none(Block)
  debug "IBD download loop start", peer, targetBlock

  while true:
    let effectiveTarget =
      if targetBlock.isSome:
        targetBlock
      else:
        let tipOpt = await sendGetTipRequest(sw, peer, chainSyncProtocol)
        if tipOpt.isNone:
          debug "IBD: GetTip failed", peer
          none(BlockId)
        else:
          case tipOpt.get.kind
          of gtrFailure:
            debug "IBD: GetTip returned failure", peer
            none(BlockId)
          of gtrTip:
            let tip = tipOpt.get.tipData.tip
            info "IBD: GetTip returned success", peer, targetBlock = sbyteutils.toHex(tip)
            some(tip)
    if effectiveTarget.isNone:
      debug "IBD: no effective target", peer
      return false
    if hasBlock(localTree, effectiveTarget.get):
      debug "IBD: target already local", peer, targetBlock = sbyteutils.toHex(effectiveTarget.get)
      return true

    let additionalKnown =
      if latestDownloaded.isSome: @[blockId(latestDownloaded.get.header)] else: @[]
    let downloadReq = DownloadBlocksRequest(
      targetBlock: effectiveTarget.get,
      knownBlocks: buildKnownBlocks(localTree, additionalKnown),
    )
    let respOpt = await sendDownloadBlocksRequest(
      sw,
      peer,
      downloadReq,
      chainSyncProtocol,
    )
    info "IBD: download request sent",
      peer,
      targetBlock = sbyteutils.toHex(downloadReq.targetBlock),
      localTip = sbyteutils.toHex(downloadReq.knownBlocks.localTip),
      latestImmutableBlock = sbyteutils.toHex(downloadReq.knownBlocks.latestImmutableBlock),
      additionalBlocks = downloadReq.knownBlocks.additionalBlocks.mapIt(sbyteutils.toHex(it))
    if respOpt.isNone:
      debug "IBD: download request failed", peer, targetBlock = sbyteutils.toHex(effectiveTarget.get)
      return false

    let msgs = respOpt.get
    let blocksOpt = decodeBlocksFromDownloadResponses(msgs)
    if blocksOpt.isNone:
      debug "IBD: download decode failed", peer, messages = msgs.len
      return false
    let blocks = blocksOpt.get
    if blocks.len == 0:
      debug "IBD: download returned no blocks", peer, targetBlock = sbyteutils.toHex(effectiveTarget.get)
      return false
    info "IBD: applying downloaded blocks", peer, count = blocks.len, targetBlock = sbyteutils.toHex(effectiveTarget.get)

    var targetReached = false
    for blk in blocks:
      latestDownloaded = some(blk)
      try:
        onBlock(localTree, blk)
        if blockId(blk.header) == effectiveTarget.get:
          targetReached = true
          break
      except CatchableError as exc:
        debug "IBD: block ingest failed", peer, exc = exc.msg
        return false

    if targetReached:
      debug "IBD: target reached", peer, targetBlock = sbyteutils.toHex(effectiveTarget.get)
      return true
    info "IBD: batch applied, continuing", peer, blocksApplied = blocks.len

proc initialBlockDownload*(
    sw: Switch,
    peers: seq[PeerId],
    localTree: LocalTree,
    chainSyncProtocol: string,
): Future[void] {.async.} =
  if peers.len == 0:
    debug "IBD skipped: no peers"
    return
  info "Starting initial block download", peerCount = peers.len, protocol = chainSyncProtocol
  var numSuccess = 0
  for peer in peers:
    if await downloadBlocks(sw, localTree, peer, Bootstrap, chainSyncProtocol, none(BlockId)):
      inc numSuccess
      info "IBD succeeded with peer", peer, successes = numSuccess

  if numSuccess == 0:
    warn "IBD failed: no peer synced successfully", peerCount = peers.len
    raise newException(IBDFailure, "Initial block download failed: no successful peer sync")

{.pop.}
