# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/sequtils,
  chronos,
  chronos/unittest2/asynctests,
  unittest2,
  results,
  ../testutil,
  ../logos_chain/sync/helpers,
  ../../logos_chain/chain/block_processor,
  ../../logos_chain/core/types
from ../../logos_chain/core/mantle/primitives import SlotNumber

template withProcessor(body: untyped) =
  let
    genesisBlk {.inject.} = createGenesisBlock(minimalSignedTx())
    gid {.inject.} = blockId(genesisBlk.header)
    bp {.inject.} = startTestProcessor(initTestChain(genesisBlk))
  try:
    body
  finally:
    await bp.stop()

suite "chain/block_processor":
  asyncTest "addBlock applies a child of genesis and completes ok":
    withProcessor:
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        r = await bp.addBlock(BlockSource.Sync, b1)
      check r.isOk
      check bp.chain.localTree.localTipId == blockId(b1.header)
      check bp.chain.ledger.state(blockId(b1.header)).isSome

  asyncTest "addBlock on an applied block completes with AlreadyApplied":
    withProcessor:
      let b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
      check (await bp.addBlock(BlockSource.Sync, b1)).isOk
      let r = await bp.addBlock(BlockSource.Gossip, b1)
      check r.isErr and r.error.kind == BlockApplyErrorKind.AlreadyApplied

  asyncTest "queue is FIFO":
    withProcessor:
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        b2 = childBlock(b1.header, blockId(b1.header), SlotNumber(2), [])
        f2 = bp.addBlock(BlockSource.Sync, b2)
        f1 = bp.addBlock(BlockSource.Sync, b1)
      check bp.hasBlocks
      check (await f2).error.kind == BlockApplyErrorKind.MissingParent
      check (await f1).isOk
      check (await bp.addBlock(BlockSource.Sync, b2)).isOk
      check not bp.hasBlocks

  asyncTest "loop yields to other tasks between blocks":
    withProcessor:
      var
        blocks = newSeqOfCap[Block](16)
        parentHdr = genesisBlk.header
        parentId = gid
      for slot in 1 .. 16:
        let blk = childBlock(parentHdr, parentId, SlotNumber(slot), [])
        blocks.add blk
        parentHdr = blk.header
        parentId = blockId(blk.header)

      # `popFirst` on a non-empty queue returns a finished future, and `await`
      # on a finished future does not return to `poll`. Without the `idleAsync`
      # line the whole queue drains inside one callback and the ticker never
      # runs while `hasBlocks` is true. With it, each poll pass promotes one
      # idler after due timers, so the ticker fires at least once per block
      # and in practice about every second poll pass. Expect a count near 23.
      var ticksWhileBusy = 0
      proc ticker() {.async: (raises: [CancelledError]).} =
        while true:
          await sleepAsync(0.milliseconds)
          if bp.hasBlocks:
            inc ticksWhileBusy
      let tickerFut = ticker()

      let futs = blocks.mapIt(bp.addBlock(BlockSource.Sync, it))
      await allFutures(futs)
      await tickerFut.cancelAndWait()
      check futs.allIt(it.read().isOk)
      check ticksWhileBusy >= blocks.len - 1

  asyncTest "a rejected block does not stall the loop":
    withProcessor:
      var fakeParentId: BlockId
      fakeParentId[0] = 7
      let
        orphan = childBlock(genesisBlk.header, fakeParentId, SlotNumber(1), [])
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
      discard bp.addBlock(BlockSource.Gossip, orphan)
      check (await bp.addBlock(BlockSource.Sync, b1)).isOk
      check not bp.chain.localTree.hasBlock(blockId(orphan.header))

  asyncTest "error kinds: MissingParent and UnviableFork":
    withProcessor:
      var fakeParentId: BlockId
      fakeParentId[0] = 7
      let
        orphan = childBlock(genesisBlk.header, fakeParentId, SlotNumber(1), [])
        stale = childBlock(genesisBlk.header, gid, SlotNumber(0), [])
      check (await bp.addBlock(BlockSource.Sync, orphan)).error.kind ==
        BlockApplyErrorKind.MissingParent
      check (await bp.addBlock(BlockSource.Sync, stale)).error.kind ==
        BlockApplyErrorKind.UnviableFork

  asyncTest "stop ends the loop and cancels later addBlock calls":
    withProcessor:
      check bp.running
      await bp.stop()
      check not bp.running
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        f = bp.addBlock(BlockSource.Sync, b1)
      await sleepAsync(1.milliseconds)
      check f.cancelled()

{.pop.}
