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

suite "chain/block_processor":
  setup:
    let
      genesisBlk = createGenesisBlock(minimalSignedTx())
      gid = blockId(genesisBlk.header)
      chain = initTestChain(genesisBlk)

  asyncTest "addBlock applies a child of genesis and completes ok":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        r = await bp.addBlock(BlockSource.Sync, b1)
      check r.isOk
      check bp.localTree.localTipId == blockId(b1.header)
      check bp.ledger.state(blockId(b1.header)).isSome

  asyncTest "addBlock on an applied block completes with AlreadyApplied":
    withProcessor(chain):
      let b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
      check (await bp.addBlock(BlockSource.Sync, b1)).isOk
      let r = await bp.addBlock(BlockSource.Gossip, b1)
      check r.isErr and r.error.kind == BlockApplyErrorKind.AlreadyApplied

  asyncTest "addBlock deduplicates in-flight blocks immediately":
    withProcessor(chain):
      let b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
      let f1 = bp.addBlock(BlockSource.Sync, b1)
      let f2 = bp.addBlock(BlockSource.Gossip, b1)
      check f2.finished
      check (await f2).error.kind == BlockApplyErrorKind.InFlight
      check (await f1).isOk

  asyncTest "queue is FIFO":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        b2 = childBlock(b1.header, blockId(b1.header), SlotNumber(2), [])
        f2 = bp.addBlock(BlockSource.Sync, b2)
        f1 = bp.addBlock(BlockSource.Sync, b1)
      check not f1.finished
      check not f2.finished
      check (await f2).error.kind == BlockApplyErrorKind.OrphanBuffered
      check (await f1).isOk
      # b2 is promoted asynchronously across event-loop turns
      while not bp.localTree.hasBlock(blockId(b2.header)):
        await sleepAsync(1.milliseconds)
      check bp.localTree.localTipId == blockId(b2.header)
      check (await bp.addBlock(BlockSource.Sync, b2)).error.kind == BlockApplyErrorKind.AlreadyApplied

  asyncTest "orphan cascade yields cooperatively between each promoted orphan":
    withProcessor(chain):
      var
        blocks = newSeqOfCap[Block](6)
        parentHdr = genesisBlk.header
        parentId = gid
      for slot in 1 .. 6:
        let blk = childBlock(parentHdr, parentId, SlotNumber(slot), [])
        blocks.add blk
        parentHdr = blk.header
        parentId = blockId(blk.header)

      # Buffer blocks 2..5 as orphans first
      for i in 1 .. 5:
        check (await bp.addBlock(BlockSource.Sync, blocks[i])).error.kind ==
          BlockApplyErrorKind.OrphanBuffered
      check bp.orphanPool.len == 5

      # Start background ticker to count event loop yields
      var ticksWhileBusy = 0
      let lastId = blockId(blocks[5].header)
      proc ticker() {.async: (raises: [CancelledError]).} =
        while true:
          await sleepAsync(0.milliseconds)
          if not bp.localTree.hasBlock(lastId):
            inc ticksWhileBusy
      let tickerFut = ticker()

      # Ingest parent block 0 -> triggers cascade promotion of blocks 1..5
      check (await bp.addBlock(BlockSource.Sync, blocks[0])).isOk

      # Wait for all orphans to be promoted
      while not bp.localTree.hasBlock(lastId):
        await sleepAsync(1.milliseconds)

      await tickerFut.cancelAndWait()
      for b in blocks:
        check bp.localTree.hasBlock(blockId(b.header))
      check bp.localTree.localTipId == lastId
      check bp.orphanPool.len == 0
      # Verify cooperative yielding occurred between orphan promotions
      check ticksWhileBusy >= 4

  asyncTest "failing promoted orphan prunes waiting descendants asynchronously":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(2), [])
        id1 = blockId(b1.header)
        # b2 has slot 2 == parent slot 2 -> passes stateless checks, but fails on promotion
        b2 = childBlock(b1.header, id1, SlotNumber(2), [])
        id2 = blockId(b2.header)
        b3 = childBlock(b2.header, id2, SlotNumber(3), [])
        id3 = blockId(b3.header)
        b4 = childBlock(b3.header, id3, SlotNumber(4), [])
        id4 = blockId(b4.header)

      # Buffer b4, b3, b2 as orphans
      check (await bp.addBlock(BlockSource.Sync, b4)).error.kind == BlockApplyErrorKind.OrphanBuffered
      check (await bp.addBlock(BlockSource.Sync, b3)).error.kind == BlockApplyErrorKind.OrphanBuffered
      check (await bp.addBlock(BlockSource.Sync, b2)).error.kind == BlockApplyErrorKind.OrphanBuffered
      check bp.orphanPool.len == 3

      # Ingest parent b1 -> triggers promotion of b2 which fails and prunes b3, b4
      check (await bp.addBlock(BlockSource.Sync, b1)).isOk

      # Allow event loop to process the promoted orphan failure
      await sleepAsync(10.milliseconds)

      check bp.localTree.hasBlock(id1)
      check not bp.localTree.hasBlock(id2)
      check not bp.localTree.hasBlock(id3)
      check not bp.localTree.hasBlock(id4)
      check bp.orphanPool.len == 0

  asyncTest "loop yields to other tasks between blocks":
    withProcessor(chain):
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
      # runs while results are pending. With it, each poll pass promotes one
      # idler after due timers, so the ticker fires at least once per block
      # and in practice about every second poll pass. Expect a count near 23.
      let futs = blocks.mapIt(bp.addBlock(BlockSource.Sync, it))
      var ticksWhileBusy = 0
      proc ticker() {.async: (raises: [CancelledError]).} =
        while true:
          await sleepAsync(0.milliseconds)
          if not futs.allIt(it.finished):
            inc ticksWhileBusy
      let tickerFut = ticker()

      await allFutures(futs)
      await tickerFut.cancelAndWait()
      check futs.allIt(it.read().isOk)
      check ticksWhileBusy >= blocks.len - 1

  asyncTest "a rejected block does not stall the loop":
    withProcessor(chain):
      var fakeParentId: BlockId
      fakeParentId[0] = 7
      let
        orphan = childBlock(genesisBlk.header, fakeParentId, SlotNumber(1), [])
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
      discard bp.addBlock(BlockSource.Gossip, orphan)
      check (await bp.addBlock(BlockSource.Sync, b1)).isOk
      check not bp.localTree.hasBlock(blockId(orphan.header))

  asyncTest "error kinds: OrphanBuffered and InvalidStructure":
    withProcessor(chain):
      var fakeParentId: BlockId
      fakeParentId[0] = 7
      let
        orphan = childBlock(genesisBlk.header, fakeParentId, SlotNumber(1), [])
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        # Same slot as its parent, but above the LIB slot so the fork gate
        # does not fire first.
        stale = childBlock(b1.header, blockId(b1.header), SlotNumber(1), [])
      check (await bp.addBlock(BlockSource.Sync, orphan)).error.kind ==
        BlockApplyErrorKind.OrphanBuffered
      check (await bp.addBlock(BlockSource.Sync, b1)).isOk
      check (await bp.addBlock(BlockSource.Sync, stale)).error.kind ==
        BlockApplyErrorKind.InvalidStructure

  asyncTest "stop ends the loop and cancels later addBlock calls":
    withProcessor(chain):
      check bp.running
      await bp.stop()
      check not bp.running
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        f = bp.addBlock(BlockSource.Sync, b1)
      await sleepAsync(1.milliseconds)
      check f.cancelled()

{.pop.}
