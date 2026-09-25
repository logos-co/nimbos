# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Queue-driven owner of the only `Chain`. Applies one block per event-loop turn.

{.push raises: [], gcsafe.}

import
  std/tables,
  chronicles,
  chronos,
  stew/byteutils,
  ./chain

export chain

logScope:
  topics = "block_processor"

const IdleTimeout = 10.milliseconds
  ## Upper bound on the wait for an idle event loop between two blocks.

type
  InFlightKey = Hash32

  BlockSource* {.pure.} = enum
    Sync
    Gossip

  BlockApplyResult = Result[void, BlockApplyError]
  BlockApplyFuture* = Future[BlockApplyResult].Raising([CancelledError])

  BlockEntryKind {.pure.} = enum
    RawIncoming
    PromotedOrphan

  BlockEntry = ref object
    queueTick: Moment
    resfut: Opt[BlockApplyFuture]
    case kind: BlockEntryKind
    of BlockEntryKind.RawIncoming:
      blk: Block
      src: BlockSource
    of BlockEntryKind.PromotedOrphan:
      admittedBlk: AdmittedBlock

  BlockProcessor* = ref object
    chain: Chain
    blockQueue: AsyncQueue[BlockEntry]
    inFlight: Table[InFlightKey, BlockEntry]
    loopFut: Future[void].Raising([CancelledError])

template inFlightKey*(id: BlockId, sig: Ed25519Signature): InFlightKey =
  ## Fast 32-byte in-flight key folding BlockId with both 32-byte halves of the
  ## Ed25519 signature (R xor S). Avoids crypto hashing overhead (~1.7ns vs ~220ns)
  ## while preserving ~252-bit Ed25519 signature entropy (collision probability
  ## ~2^-252, matching a 256-bit cryptographic hash's 2^-256) so invalid blocks
  ## with junk signatures cannot lock out valid blocks.
  var res {.noinit.}: InFlightKey
  for i in 0 ..< 32:
    res[i] = id[i] xor sig.data[i] xor sig.data[32 + i]
  res

proc new*(T: type BlockProcessor, chain: sink Chain): T =
  T(chain: chain, blockQueue: newAsyncQueue[BlockEntry]())

func localTree*(bp: BlockProcessor): LocalTree =
  bp.chain.localTree

func ledger*(bp: BlockProcessor): lent Ledger[BlockId] =
  bp.chain.ledger

func mempool*(bp: BlockProcessor): Mempool =
  bp.chain.mempool

proc currentWallclockSlot*(bp: BlockProcessor): SlotNumber =
  bp.chain.currentWallclockSlot()

func running*(bp: BlockProcessor): bool =
  bp.loopFut != nil and not bp.loopFut.finished

func checkDeduplication*(
    bp: BlockProcessor, id: BlockId, sig: Ed25519Signature
): Result[void, BlockApplyErrorKind] =
  let key = inFlightKey(id, sig)
  if key in bp.inFlight:
    return err(BlockApplyErrorKind.InFlight)
  if bp.chain.localTree.hasBlock(id):
    return err(BlockApplyErrorKind.AlreadyApplied)
  if bp.chain.orphanPool.hasOrphan(id):
    return err(BlockApplyErrorKind.OrphanAlreadyBuffered)
  ok()

proc addBlock*(
    bp: BlockProcessor,
    src: BlockSource,
    blk: sink Block,
    id: BlockId,
): BlockApplyFuture =
  ## Queue `blk`. The future completes with the apply result, or is cancelled
  ## when the loop is not running. Cancelling it does not dequeue the block.
  let resfut = BlockApplyFuture.init("BlockProcessor.addBlock")
  if not bp.running:
    resfut.cancelSoon()
    return resfut

  bp.checkDeduplication(id, blk.signature).isOkOr:
    resfut.complete(BlockApplyResult.err(BlockApplyError(kind: error)))
    return resfut

  let key = inFlightKey(id, blk.signature)
  let entry = BlockEntry(
    kind: BlockEntryKind.RawIncoming,
    blk: blk,
    src: src,
    resfut: Opt.some(resfut),
    queueTick: Moment.now(),
  )
  bp.inFlight[key] = entry
  try:
    bp.blockQueue.addLastNoWait(entry)
  except AsyncQueueFullError:
    bp.inFlight.del(key)
    raiseAssert "unbounded queue cannot be full"
  resfut

proc enqueueOrphanBlock(bp: BlockProcessor, child: AdmittedBlock) =
  let childId = blockId(header(child))
  let key = inFlightKey(childId, child.signature)
  var stolenResfut = Opt.none(BlockApplyFuture)

  bp.inFlight.withValue(key, existing):
    # A raw copy is queued — supersede it and steal its caller future.
    if existing[].kind == BlockEntryKind.RawIncoming:
      stolenResfut = existing[].resfut
      existing[].resfut = Opt.none(BlockApplyFuture)

  let entry = BlockEntry(
    kind: BlockEntryKind.PromotedOrphan,
    queueTick: Moment.now(),
    admittedBlk: child,
    resfut: stolenResfut,
  )
  bp.inFlight[key] = entry
  try:
    bp.blockQueue.addFirstNoWait(entry)
  except AsyncQueueFullError:
    bp.inFlight.del(key)
    raiseAssert "unbounded queue cannot be full"

proc processBlock(bp: BlockProcessor, entry: BlockEntry) =
  if entry.kind == BlockEntryKind.RawIncoming and entry.resfut.isNone:
    return

  let (id, key) = case entry.kind
    of BlockEntryKind.RawIncoming:
      let i = blockId(header(entry.blk))
      (i, inFlightKey(i, entry.blk.signature))
    of BlockEntryKind.PromotedOrphan:
      let i = blockId(header(entry.admittedBlk))
      (i, inFlightKey(i, entry.admittedBlk.signature))
  defer:
    bp.inFlight.del(key)

  let
    startTick = Moment.now()
    res = case entry.kind
      of BlockEntryKind.RawIncoming: bp.chain.tryApplyBlock(entry.blk)
      of BlockEntryKind.PromotedOrphan: bp.chain.tryApplyAdmittedBlock(entry.admittedBlk)
    applyDur = Moment.now() - startTick
    queueDur = startTick - entry.queueTick

  res.isOkOr:
    case entry.kind
    of BlockEntryKind.RawIncoming:
      debug "Block rejected",
        id = toHex(id), slot = header(entry.blk).slot,
        src = entry.src, queueDur, applyDur, err = error.kind
    of BlockEntryKind.PromotedOrphan:
      debug "Promoted orphan rejected",
        id = toHex(id), slot = header(entry.admittedBlk).slot,
        queueDur, applyDur, err = error.kind
    if entry.resfut.isSome:
      entry.resfut.get().complete(BlockApplyResult.err(error))
    return

  for child in bp.chain.orphanPool.takeChildren(id):
    bp.enqueueOrphanBlock(child)

  case entry.kind
  of BlockEntryKind.RawIncoming:
    debug "Block applied",
      id = toHex(id), slot = header(entry.blk).slot,
      src = entry.src, queueDur, applyDur
  of BlockEntryKind.PromotedOrphan:
    debug "Promoted orphan applied",
      id = toHex(id), slot = header(entry.admittedBlk).slot,
      queueDur, applyDur
  if entry.resfut.isSome:
    entry.resfut.get().complete(BlockApplyResult.ok())

proc runQueueProcessingLoop(bp: BlockProcessor) {.async: (raises: [CancelledError]).} =
  while true:
    # One block per turn; networking shares the thread. The timeout caps the
    # wait when the network never goes idle.
    let idleTick = Moment.now()
    discard await idleAsync().withTimeout(IdleTimeout)
    # TODO nim-metrics histogram
    debug "Idle wait before block", idleDur = Moment.now() - idleTick
    bp.processBlock(await bp.blockQueue.popFirst())

proc start*(bp: BlockProcessor) =
  doAssert bp.loopFut == nil, "block processor already started"
  bp.loopFut = bp.runQueueProcessingLoop()

proc stop*(bp: BlockProcessor) {.async: (raises: []).} =
  ## Cancel the loop and cancel every result future still queued.
  if bp.loopFut == nil:
    return
  await bp.loopFut.cancelAndWait()
  bp.loopFut = nil
  for entry in bp.blockQueue.items:
    if entry.resfut.isSome:
      entry.resfut.get().cancelSoon()
  bp.blockQueue.clear()
  bp.inFlight.clear()

{.pop.}
