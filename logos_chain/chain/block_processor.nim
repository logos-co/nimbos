# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Queue-driven owner of the only `Chain`. Applies one block per event-loop turn.

{.push raises: [], gcsafe.}

import
  chronicles,
  chronos,
  results,
  stew/byteutils,
  ./chain

from ../core/types import Block, BlockId, blockId, header

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

  BlockEntry = ref object
    blk: Block
    src: BlockSource
    resfut: BlockApplyFuture
    queueTick: Moment

  BlockProcessor* = ref object
    chain: Chain
    blockQueue: AsyncQueue[BlockEntry]
    loopFut: Future[void].Raising([CancelledError])

proc new*(T: type BlockProcessor, chain: sink Chain): T =
  T(chain: chain, blockQueue: newAsyncQueue[BlockEntry]())

func localTree*(bp: BlockProcessor): LocalTree =
  bp.chain.localTree

func ledger*(bp: BlockProcessor): lent Ledger[BlockId] =
  bp.chain.ledger

func hasBlocks*(bp: BlockProcessor): bool =
  bp.blockQueue.len > 0

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
  try:
    bp.blockQueue.addLastNoWait(BlockEntry(
      blk: blk, src: src, resfut: resfut, queueTick: Moment.now()))
  except AsyncQueueFullError:
    raiseAssert "unbounded queue cannot be full"
  resfut

proc processBlock(bp: BlockProcessor, entry: BlockEntry) =
  let
    startTick = Moment.now()
    res = bp.chain.tryApplyBlock(entry.blk)
    applyDur = Moment.now() - startTick
    queueDur = startTick - entry.queueTick
  if res.isOk:
    debug "Block applied",
      id = toHex(blockId(header(entry.blk))), slot = header(entry.blk).slot,
      src = entry.src, queueDur, applyDur
  else:
    debug "Block rejected",
      id = toHex(blockId(header(entry.blk))), slot = header(entry.blk).slot,
      src = entry.src, queueDur, applyDur, err = res.error.kind
  entry.resfut.complete(res)

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
  while bp.blockQueue.len > 0:
    let entry = try:
      bp.blockQueue.popFirstNoWait()
    except AsyncQueueEmptyError:
      raiseAssert "queue length checked above"
    entry.resfut.cancelSoon()

{.pop.}
