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
  results,
  stew/byteutils,
  ./chain

from ../core/types import Block, BlockId, AdmittedBlock, blockId, header

export chain

logScope:
  topics = "block_processor"

const IdleTimeout = 10.milliseconds
  ## Upper bound on the wait for an idle event loop between two blocks.

type
  BlockSource* {.pure.} = enum
    Sync
    Gossip

  BlockApplyResult* = Result[void, BlockApplyError]
  BlockApplyFuture* = Future[BlockApplyResult].Raising([CancelledError])

  BlockEntryKind = enum
    RawIncoming
    PromotedOrphan

  BlockEntry = ref object
    queueTick: Moment
    resfut: Opt[BlockApplyFuture]
    case kind: BlockEntryKind
    of RawIncoming:
      blk: Block
      src: BlockSource
    of PromotedOrphan:
      admittedBlk: AdmittedBlock

  BlockProcessor* = ref object
    chain: Chain
    blockQueue: AsyncQueue[BlockEntry]
    inFlight: Table[BlockId, BlockEntry]
    loopFut: Future[void].Raising([CancelledError])

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

func orphanPool*(bp: BlockProcessor): OrphanPool =
  bp.chain.orphanPool

func running*(bp: BlockProcessor): bool =
  bp.loopFut != nil and not bp.loopFut.finished

proc addBlock*(
    bp: BlockProcessor, src: BlockSource, blk: sink Block): BlockApplyFuture =
  ## Queue `blk`. The future completes with the apply result, or is cancelled
  ## when the loop is not running. Cancelling it does not dequeue the block.
  let resfut = BlockApplyFuture.init("BlockProcessor.addBlock")
  if not bp.running:
    resfut.cancelSoon()
    return resfut

  let id = blockId(header(blk))
  # Ingestion deduplication: check if in-flight, already applied, or buffered as orphan
  if id in bp.inFlight:
    resfut.complete(BlockApplyResult.err(BlockApplyError(kind: InFlight)))
    return resfut
  if bp.chain.localTree.hasBlock(id):
    resfut.complete(BlockApplyResult.err(BlockApplyError(kind: AlreadyApplied)))
    return resfut
  if bp.chain.orphanPool.hasOrphan(id):
    resfut.complete(BlockApplyResult.err(BlockApplyError(kind: OrphanAlreadyBuffered)))
    return resfut

  let entry = BlockEntry(
    kind: RawIncoming,
    blk: blk,
    src: src,
    resfut: Opt.some(resfut),
    queueTick: Moment.now(),
  )
  bp.inFlight[id] = entry
  try:
    bp.blockQueue.addLastNoWait(entry)
  except AsyncQueueFullError:
    bp.inFlight.del(id)
    raiseAssert "unbounded queue cannot be full"
  resfut

proc enqueueOrphanBlock(bp: BlockProcessor, child: AdmittedBlock) =
  let childId = blockId(header(child))
  var stolenResfut = Opt.none(BlockApplyFuture)

  bp.inFlight.withValue(childId, existing):
    # A raw copy is queued — supersede it and steal its caller future.
    if existing[].kind == RawIncoming:
      stolenResfut = existing[].resfut
      existing[].resfut = Opt.none(BlockApplyFuture)

  let entry = BlockEntry(
    kind: PromotedOrphan,
    queueTick: Moment.now(),
    admittedBlk: child,
    resfut: stolenResfut,
  )
  bp.inFlight[childId] = entry
  try:
    bp.blockQueue.addFirstNoWait(entry)
  except AsyncQueueFullError:
    bp.inFlight.del(childId)
    raiseAssert "unbounded queue cannot be full"

proc processBlock(bp: BlockProcessor, entry: BlockEntry) =
  if entry.kind == RawIncoming and entry.resfut.isNone:
    return

  let id = case entry.kind
    of RawIncoming: blockId(header(entry.blk))
    of PromotedOrphan: blockId(header(entry.admittedBlk))
  defer:
    bp.inFlight.del(id)

  let
    startTick = Moment.now()
    res = case entry.kind
      of RawIncoming: bp.chain.tryApplyBlock(entry.blk)
      of PromotedOrphan: bp.chain.tryApplyAdmittedBlock(entry.admittedBlk)
    applyDur = Moment.now() - startTick
    queueDur = startTick - entry.queueTick

  res.isOkOr:
    case entry.kind
    of RawIncoming:
      debug "Block rejected",
        id = toHex(id), slot = header(entry.blk).slot,
        src = entry.src, queueDur, applyDur, err = error.kind
    of PromotedOrphan:
      debug "Promoted orphan rejected",
        id = toHex(id), slot = header(entry.admittedBlk).slot,
        queueDur, applyDur, err = error.kind
    if entry.resfut.isSome:
      entry.resfut.get().complete(BlockApplyResult.err(error))
    return

  for child in bp.chain.orphanPool.takeChildren(id):
    bp.enqueueOrphanBlock(child)

  case entry.kind
  of RawIncoming:
    debug "Block applied",
      id = toHex(id), slot = header(entry.blk).slot,
      src = entry.src, queueDur, applyDur
  of PromotedOrphan:
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
