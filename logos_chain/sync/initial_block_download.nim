# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  std/sets,
  chronicles,
  chronos,
  results,
  libp2p/[switch, peerid, errors],
  libp2p/protocols/protocol,
  libp2p/stream/connection,
  stew/endians2,
  stew/byteutils as sbyteutils

import ../core/local_tree
import ../core/block_validation
import ./config
import ./types

from ../core/types import Block, BlockId, blockId
from ../core/mantle/primitives import SlotNumber
from libp2p/crypto/ed25519/ed25519 import EdPublicKeySize, toBytes

export types

logScope:
  topics = "cryptarchia_ibd"

# ---------------------------------------------------------------------------
# Wire framing (u32 inner length, raw stream write/read)
# ---------------------------------------------------------------------------

proc readCryptarchiaPrefixedInner*(conn: Connection): Future[Opt[seq[byte]]] {.async.} =
  ## Read LE ``uint32`` inner length, then exactly ``innerLen`` bytes.
  try:
    var lenPrefix = newSeqUninit[byte](CryptarchiaSyncInnerLengthPrefixSize)
    await conn.readExactly(addr lenPrefix[0], CryptarchiaSyncInnerLengthPrefixSize)
    let innerLen = int(uint32.fromBytesLE(lenPrefix.toOpenArray(
        0, CryptarchiaSyncInnerLengthPrefixSize - 1)))
    if innerLen == 0:
      return Opt.some(newSeq[byte]())
    var inner = newSeqUninit[byte](innerLen)
    await conn.readExactly(addr inner[0], innerLen)
    debug "IBD wire read ok", innerBytes = inner.len
    Opt.some(inner)
  except CatchableError as exc:
    debug "IBD wire read failed", exc = exc.msg
    Opt.none(seq[byte])

proc writeCryptarchiaPrefixedInner*(conn: Connection, inner: seq[byte]) {.async.} =
  ## Prepend LE ``uint32`` inner length, then ``write`` the frame raw on the stream.
  let framed = addPrefixLengthToPayload(inner)
  debug "IBD wire write",
    innerBytes = inner.len,
    framedBytes = framed.len,
    innerHex = sbyteutils.toHex(inner),
    framedHex = sbyteutils.toHex(framed)
  await conn.write(framed)
  debug "IBD wire write ok", framedBytes = framed.len

func parseRequestMessageKind*(inner: openArray[byte]): Opt[RequestMessageKind] {.raises: [].} =
  ## First 4 bytes of the inner bincode body are ``RequestMessageKind`` (u32 LE).
  const kindWireSize = sizeof(uint32)
  if inner.len < kindWireSize:
    return Opt.none(RequestMessageKind)
  let w = uint32.fromBytesLE(inner.toOpenArray(0, kindWireSize - 1))
  if w > uint32(ord(high(RequestMessageKind))):
    return Opt.none(RequestMessageKind)
  Opt.some(RequestMessageKind(w))

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
): Future[Opt[GetTipResponse]] {.async.} =
  var wireReq: seq[byte]
  debug "IBD GetTip request", peer, protocol = chainSyncProtocol
  try:
    wireReq = serializeRequestMessageToSeq(
      RequestMessage(kind: rmGetTip), cryptarchiaSyncBincodeConfig)
    debug "IBD GetTip serialize ok", peer, requestBytes = wireReq.len
  except CatchableError as exc:
    debug "IBD GetTip serialize failed", peer, exc = exc.msg
    return Opt.none(GetTipResponse)
  var conn: Connection
  try:
    debug "IBD GetTip dialing",
      peer,
      protocol = chainSyncProtocol,
      peerConnected = sw.isConnected(peer)
    conn = await sw.dial(peer, chainSyncProtocol)
    debug "IBD GetTip dial ok", peer, protocol = conn.protocol
  except CatchableError as exc:
    debug "IBD GetTip dial failed", peer, exc = exc.msg, peerConnected = sw.isConnected(peer)
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
    except CatchableError as exc:
      debug "IBD GetTip deserialize failed", peer, exc = exc.msg
      return Opt.none(GetTipResponse)
  except CatchableError as exc:
    debug "IBD GetTip exchange failed", peer, exc = exc.msg
    return Opt.none(GetTipResponse)
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

func decodeBlocksFromDownloadResponses*(messages: seq[DownloadBlocksResponse]): Opt[seq[Block]] {.raises: [].} =
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
      except CatchableError:
        Opt.none(Block)
      let blk = blkOpt.valueOr:
        return Opt.none(seq[Block])
      blks.add blk
  Opt.some(blks)

proc sendDownloadBlocksRequest*(
    sw: Switch,
    peer: PeerId,
    request: DownloadBlocksRequest,
    chainSyncProtocol: string,
): Future[Opt[seq[DownloadBlocksResponse]]] {.async.} =
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
  except CatchableError as exc:
    debug "IBD download serialize failed", peer, exc = exc.msg
    return Opt.none(seq[DownloadBlocksResponse])
  var conn: Connection
  try:
    debug "IBD download dialing",
      peer,
      protocol = chainSyncProtocol,
      peerConnected = sw.isConnected(peer)
    conn = await sw.dial(peer, chainSyncProtocol)
    debug "IBD download dial ok", peer, protocol = conn.protocol
  except CatchableError as exc:
    debug "IBD download dial failed", peer, exc = exc.msg, peerConnected = sw.isConnected(peer)
    return Opt.none(seq[DownloadBlocksResponse])
  try:
    await writeCryptarchiaPrefixedInner(conn, wireReq)
    debug "IBD download write ok", peer, requestBytes = wireReq.len
    var acc = newSeqOfCap[DownloadBlocksResponse](64)
    while true:
      let inner = (await readCryptarchiaPrefixedInner(conn)).valueOr:
        debug "IBD download response read failed", peer, messages = acc.len
        return Opt.none(seq[DownloadBlocksResponse])
      debug "IBD download read ok",
        peer,
        responseBytes = inner.len,
        messageIndex = acc.len,
        innerHex = sbyteutils.toHex(inner)
      let msgOpt = try:
        Opt.some(deserializeDownloadBlocksResponse(inner, cryptarchiaSyncBincodeConfig))
      except CatchableError as exc:
        debug "IBD download response deserialize failed", peer, exc = exc.msg
        Opt.none(DownloadBlocksResponse)
      let msg = msgOpt.valueOr:
        return Opt.none(seq[DownloadBlocksResponse])
      acc.add msg
      case msg.kind
      of dbrFailure:
        debug "IBD download deserialize ok (failure)",
          peer, failureMessage = msg.failureMessage, messageIndex = acc.high
        break
      of dbrNoMoreBlocks:
        debug "IBD download deserialize ok (no more blocks)",
          peer, messages = acc.len
        break
      of dbrBlock:
        debug "IBD download deserialize ok (block)",
          peer, blockBytes = msg.downloadedBlock.len, messageIndex = acc.high
    debug "IBD download exchange complete", peer, messages = acc.len
    Opt.some(acc)
  except CatchableError as exc:
    debug "IBD download exchange failed", peer, exc = exc.msg
    return Opt.none(seq[DownloadBlocksResponse])
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
    let lca = lcaBlockId(localTree, kid, target).valueOr:
      continue
    let h = localTree.blockHeight(lca).valueOr:
      continue
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
    let blk = localTree.getBlock(curId).valueOr:
      return @[]
    rev.add blk
    curId = blk.header.parentBlock
    if curId == default(BlockId):
      return @[]
  var forward = newSeqOfCap[Block](rev.len)
  for i in countdown(rev.high, 0):
    forward.add rev[i]
  forward

template awaitWriteDlRespLp(conn: Connection, msg: DownloadBlocksResponse) =
  ## u32-prefixed inner + raw ``write``; skips write when encoding yields empty.
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
      let inner = (await readCryptarchiaPrefixedInner(conn)).valueOr:
        debug "IBD handler: request read failed"
        return
      debug "IBD handler: request read ok", requestBytes = inner.len
      let kind = parseRequestMessageKind(inner).valueOr:
        debug "IBD handler: invalid request kind"
        return
      case kind
      of rmGetTip:
        debug "IBD handler: GetTip request"
        let tipResp = getTipResponseFromLocalTree(localTree)
        let respInner = try:
          serializeGetTipResponseToSeq(tipResp, cryptarchiaSyncBincodeConfig)
        except CatchableError as exc:
          debug "IBD handler: GetTip serialize failed", exc = exc.msg
          @[]
        if respInner.len > 0:
          await writeCryptarchiaPrefixedInner(conn, respInner)
          debug "IBD handler: GetTip response ok",
            responseBytes = respInner.len,
            tip = sbyteutils.toHex(tipResp.tipData.tip),
            height = tipResp.tipData.height
      of rmDownloadBlocksRequest:
        debug "IBD handler: download blocks request"
        let reqMsgOpt = try:
          Opt.some(deserializeRequestMessage(inner, cryptarchiaSyncBincodeConfig))
        except CatchableError:
          Opt.none(RequestMessage)
        let reqMsg = reqMsgOpt.valueOr:
          debug "IBD handler: download request decode failed"
          return
        if reqMsg.kind != rmDownloadBlocksRequest:
          debug "IBD handler: download request decode failed"
          return
        debug "IBD handler: download request decode ok",
          targetBlock = sbyteutils.toHex(reqMsg.downloadBlocksRequest.targetBlock)
        let req = reqMsg.downloadBlocksRequest
        if not localTree.hasBlock(req.targetBlock):
          debug "IBD handler: target block not found", targetBlock = sbyteutils.toHex(req.targetBlock)
          awaitWriteDlRespLp(conn, DownloadBlocksResponse(
            kind: dbrFailure, failureMessage: "start block not found"))
          debug "IBD handler: download failure response ok", targetBlock = sbyteutils.toHex(req.targetBlock)
        else:
          let blocks = collectBlocksForDownloadRequest(localTree, req)
          if blocks.len == 0:
            debug "IBD handler: no blocks to send", targetBlock = sbyteutils.toHex(req.targetBlock)
            awaitWriteDlRespLp(conn, DownloadBlocksResponse(kind: dbrNoMoreBlocks))
            debug "IBD handler: download no-more-blocks response ok", targetBlock = sbyteutils.toHex(req.targetBlock)
          else:
            debug "IBD handler: sending blocks", targetBlock = sbyteutils.toHex(req.targetBlock), count = blocks.len
            var blocksSent = 0
            for blk in blocks:
              let innerWire = try:
                serializeBlockToSeq(blk, cryptarchiaSyncBincodeConfig)
              except CatchableError:
                @[]
              if innerWire.len == 0 or innerWire.len > MaxBlockSize:
                debug "IBD handler: block encode failed or too large", blockBytes = innerWire.len
                awaitWriteDlRespLp(conn, DownloadBlocksResponse(
                  kind: dbrFailure, failureMessage: "block encode failed"))
                debug "IBD handler: download failure response ok", targetBlock = sbyteutils.toHex(req.targetBlock)
                return
              awaitWriteDlRespLp(conn, DownloadBlocksResponse(kind: dbrBlock, downloadedBlock: innerWire))
              inc blocksSent
            awaitWriteDlRespLp(conn, DownloadBlocksResponse(kind: dbrNoMoreBlocks))
            debug "IBD handler: download blocks response ok",
              targetBlock = sbyteutils.toHex(req.targetBlock), blocksSent = blocksSent
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
    targetBlock: Opt[BlockId] = Opt.none(BlockId),
): Future[bool] {.async.} =
  discard forkChoice
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
        let tipOpt = await sendGetTipRequest(sw, peer, chainSyncProtocol)
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
    if hasBlock(localTree, effectiveTarget.get):
      debug "IBD: target already local", peer, targetBlock = sbyteutils.toHex(effectiveTarget.get)
      return true

    let additionalKnown = latestDownloaded
      .map(proc (b: Block): seq[BlockId] = @[blockId(b.header)])
      .valueOr(@[])
    let downloadReq = DownloadBlocksRequest(
      targetBlock: effectiveTarget.get,
      knownBlocks: buildKnownBlocks(localTree, additionalKnown),
    )
    let msgs = (await sendDownloadBlocksRequest(
      sw,
      peer,
      downloadReq,
      chainSyncProtocol,
    )).valueOr:
      debug "IBD: download request failed", peer, targetBlock = sbyteutils.toHex(effectiveTarget.get)
      return false

    for msg in msgs:
      if msg.kind == dbrFailure:
        debug "IBD: download peer failure",
          peer,
          targetBlock = sbyteutils.toHex(downloadReq.targetBlock),
          failureMessage = msg.failureMessage
        return false
    debug "IBD: download response ok", peer, messages = msgs.len, targetBlock = sbyteutils.toHex(downloadReq.targetBlock)
    let blocks = decodeBlocksFromDownloadResponses(msgs).valueOr:
      debug "IBD: block decode failed", peer, messages = msgs.len
      return false
    debug "IBD: block decode ok", peer, blocks = blocks.len, targetBlock = sbyteutils.toHex(effectiveTarget.get)
    if blocks.len == 0:
      debug "IBD: download returned no blocks", peer, targetBlock = sbyteutils.toHex(effectiveTarget.get)
      return false
    info "IBD: applying downloaded blocks", peer, count = blocks.len, targetBlock = sbyteutils.toHex(effectiveTarget.get)

    var targetReached = false
    for blk in blocks:
      latestDownloaded = Opt.some(blk)
      try:
        onBlock(localTree, blk)
        debug "IBD: block ingest ok", peer, blockId = sbyteutils.toHex(blockId(blk.header))
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
    debug "IBD: syncing peer", peer
    if await downloadBlocks(sw, localTree, peer, Bootstrap, chainSyncProtocol, Opt.none(BlockId)):
      inc numSuccess
      info "IBD succeeded with peer", peer, successes = numSuccess
    else:
      debug "IBD: peer sync failed", peer

  if numSuccess == 0:
    warn "IBD failed: no peer synced successfully", peerCount = peers.len
    raise newException(IBDFailure, "Initial block download failed: no successful peer sync")

{.pop.}
