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
      genesisBlk = createGenesisBlock(minimalValidSignedTx())
      gid = blockId(genesisBlk.header)
      chain = initTestChain(genesisBlk)

  asyncTest "addBlock applies a child of genesis and completes ok":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        r = await bp.addBlock(b1)
      check r.isOk
      check bp.localTree.localTipId == blockId(b1.header)
      check bp.ledger.state(blockId(b1.header)).isSome

  asyncTest "addBlock on an applied block completes with AlreadyApplied":
    withProcessor(chain):
      let b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
      check (await bp.addBlock(b1)).isOk
      let r = await bp.addBlock(b1)
      check r.isErr and r.error.kind == BlockApplyErrorKind.AlreadyApplied

  asyncTest "queue is FIFO":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        b2 = childBlock(b1.header, blockId(b1.header), SlotNumber(2), [])
        f2 = bp.addBlock(b2)
        f1 = bp.addBlock(b1)
      check not f1.finished
      check not f2.finished
      check (await f2).error.kind == BlockApplyErrorKind.OrphanBuffered
      check (await f1).isOk
      check (await bp.addBlock(b2)).error.kind == BlockApplyErrorKind.AlreadyApplied
      check bp.localTree.localTipId == blockId(b2.header)

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
      let futs = blocks.mapIt(bp.addBlock(it))
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
      discard bp.addBlock(orphan)
      check (await bp.addBlock(b1)).isOk
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
      check (await bp.addBlock(orphan)).error.kind ==
        BlockApplyErrorKind.OrphanBuffered
      check (await bp.addBlock(b1)).isOk
      check (await bp.addBlock(stale)).error.kind ==
        BlockApplyErrorKind.InvalidStructure

  asyncTest "addBlock on Proposal reconstructs, validates, and applies child of genesis":
    withProcessor(chain):
      let
        b1 = childValidBlock(genesisBlk.header, gid, SlotNumber(1), [])
        p1 = Proposal(header: b1.header, references: default(References), signature: b1.signature)
        r = await bp.addBlock(p1)
      check r.isOk
      check bp.localTree.localTipId == blockId(p1.header)
      check bp.ledger.state(blockId(p1.header)).isSome

  asyncTest "addBlock on Proposal with missing tx reference fails with MissingReference":
    withProcessor(chain):
      var refs: References
      refs[0] = minimalValidSignedTx().hash
      let
        b1 = childValidBlock(genesisBlk.header, gid, SlotNumber(1), [])
        p1 = Proposal(header: b1.header, references: refs, signature: b1.signature)
        r = await bp.addBlock(p1)
      check r.isErr
      check r.error.kind == BlockApplyErrorKind.MissingReference

  asyncTest "stop ends the loop and cancels later addBlock calls":
    withProcessor(chain):
      check bp.running
      await bp.stop()
      check not bp.running
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        f = bp.addBlock(b1)
      await sleepAsync(1.milliseconds)
      check f.cancelled()

{.pop.}
