# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/times,
  unittest2,
  results,
  ../testutil,
  ../logos_chain/sync/helpers,
  ../../logos_chain/core/types,
  ../../logos_chain/chain/[chain, genesis]
from ../../logos_chain/core/mantle/primitives import SlotNumber

proc setupChain(
    securityParam: uint64 = 10'u64,
): tuple[chain: Chain, genesis: ValidBlock, gid: BlockId] =
  let
    sm = minimalValidSignedTx()
    genesis = createGenesisBlock(sm)
    gid = blockId(genesis.header)
  var c = initTestChain(genesis, securityParam = securityParam)
  c.slotConfig.genesisTime = uint64(getTime().toUnix() - 500)
  var s = c.ledger.state(gid).get()
  s.feeMarket.executionBaseFee = 0
  s.feeMarket.storageGasPrice = 0
  c.ledger.commitUpdate(gid, s)
  (c, genesis, gid)

suite "chain/orphan_resolution":
  test "buffers out-of-order block and promotes it when parent arrives":
    var (chain, genesis, gid) = setupChain()

    let
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, SlotNumber(2), [])
      id2 = blockId(b2.header)

    # 1. Ingest child B2 before parent B1
    let applyB2Res = chain.tryApplyBlock(b2)
    check applyB2Res.isErr
    check applyB2Res.error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.orphanPool.hasOrphan(id2)
    check not chain.localTree.hasBlock(id2)
    check chain.localTree.localTipId == gid

    # Ingesting child B2 again returns OrphanAlreadyBuffered
    let applyB2DupRes = chain.tryApplyBlock(b2)
    check applyB2DupRes.isErr
    check applyB2DupRes.error.kind == BlockApplyErrorKind.OrphanAlreadyBuffered

    # 2. Ingest parent B1
    let applyB1Res = chain.tryApplyBlock(b1)
    check applyB1Res.isOk

    # 3. Both B1 and B2 should now be applied and promoted
    check chain.localTree.hasBlock(id1)
    check chain.localTree.hasBlock(id2)
    check chain.localTree.localTipId == id2
    check chain.ledger.state(id1).isSome
    check chain.ledger.state(id2).isSome
    check chain.orphanPool.len == 0

  test "multi-depth cascade: resolves B2, B3, B4 when B1 arrives":
    var (chain, genesis, gid) = setupChain()

    let
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, SlotNumber(2), [])
      id2 = blockId(b2.header)
      b3 = childBlock(b2.header, id2, SlotNumber(3), [])
      id3 = blockId(b3.header)
      b4 = childBlock(b3.header, id3, SlotNumber(4), [])
      id4 = blockId(b4.header)

    # Ingest B4, B3, B2 out of order
    check chain.tryApplyBlock(b4).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.tryApplyBlock(b3).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.tryApplyBlock(b2).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.orphanPool.len == 3

    # Ingest B1
    check chain.tryApplyBlock(b1).isOk

    # All 4 blocks must be applied in order
    check chain.localTree.hasBlock(id1)
    check chain.localTree.hasBlock(id2)
    check chain.localTree.hasBlock(id3)
    check chain.localTree.hasBlock(id4)
    check chain.localTree.localTipId == id4
    check chain.orphanPool.len == 0

  test "structurally invalid block or invalid header is rejected and not buffered":
    var (chain, genesis, gid) = setupChain()

    var invalidHdrBlock = childBlock(genesis.header, gid, SlotNumber(1), [])
    invalidHdrBlock.header.bedrockVersion = 99'u8 # invalid version
    let applyHdrRes = chain.tryApplyBlock(invalidHdrBlock)
    check applyHdrRes.isErr
    check applyHdrRes.error.kind == BlockApplyErrorKind.InvalidStructure
    check chain.orphanPool.len == 0

    var invalidStructBlock = childBlock(genesis.header, gid, SlotNumber(1), [])
    invalidStructBlock.signature = DefaultEd25519Signature # zero signature
    let applyStructRes = chain.tryApplyBlock(invalidStructBlock)
    check applyStructRes.isErr
    check applyStructRes.error.kind == BlockApplyErrorKind.InvalidStructure
    check chain.orphanPool.len == 0

  test "chain respects MaxOrphans capacity limit and evicts oldest":
    var (chain, _, gid) = setupChain()

    var
      blocks: seq[Block]
      parent = gid
    for i in 1 .. MaxOrphans + 2:
      let blk = childBlock(chain.genesisBlock.header, parent, SlotNumber(i), [])
      blocks.add(blk)
      parent = blockId(blk.header)

    # Ingest MaxOrphans orphans (from index 1 onward, parent missing because blocks[0] not added)
    for i in 1 .. MaxOrphans:
      check chain.tryApplyBlock(blocks[i]).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.orphanPool.len == MaxOrphans
    check chain.orphanPool.hasOrphan(blockId(blocks[1].header))

    # Ingest blocks[MaxOrphans + 1] (evicts oldest blocks[1] and purges its descendant chain)
    check chain.tryApplyBlock(blocks[MaxOrphans + 1]).error.kind == BlockApplyErrorKind.OrphanBuffered
    check not chain.orphanPool.hasOrphan(blockId(blocks[1].header))
    check not chain.orphanPool.hasOrphan(blockId(blocks[2].header))
    check chain.orphanPool.hasOrphan(blockId(blocks[MaxOrphans + 1].header))
    check chain.orphanPool.len == 1

  test "chain re-buffers evicted orphan and resolves cascade upon parent arrival":
    var (chain, _, gid) = setupChain()

    var
      blocks: seq[Block]
      parent = gid
    for i in 1 .. MaxOrphans + 2:
      let blk = childBlock(chain.genesisBlock.header, parent, SlotNumber(i), [])
      blocks.add(blk)
      parent = blockId(blk.header)

    # Ingest blocks[1 .. MaxOrphans]
    for i in 1 .. MaxOrphans:
      check chain.tryApplyBlock(blocks[i]).error.kind == BlockApplyErrorKind.OrphanBuffered

    # Ingest blocks[MaxOrphans + 1] (evicts blocks[1] and purges descendant chain)
    check chain.tryApplyBlock(blocks[MaxOrphans + 1]).error.kind == BlockApplyErrorKind.OrphanBuffered
    check not chain.orphanPool.hasOrphan(blockId(blocks[1].header))

    # Re-ingest blocks[1 .. MaxOrphans - 1] in sequential order (fitting within capacity alongside MaxOrphans + 1)
    for i in 1 .. MaxOrphans - 1:
      check chain.tryApplyBlock(blocks[i]).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.orphanPool.hasOrphan(blockId(blocks[1].header))
    check chain.orphanPool.hasOrphan(blockId(blocks[MaxOrphans + 1].header))
    check chain.orphanPool.len == MaxOrphans

    # Ingest parent blocks[0] (child of genesis) -> cascade-promotes blocks[0 .. MaxOrphans - 1]
    check chain.tryApplyBlock(blocks[0]).isOk
    for i in 0 .. MaxOrphans - 1:
      check chain.localTree.hasBlock(blockId(blocks[i].header))
    check chain.localTree.localTipId == blockId(blocks[MaxOrphans - 1].header)
    check chain.orphanPool.len == 1 # only blocks[MaxOrphans + 1] remains
    check chain.orphanPool.hasOrphan(blockId(blocks[MaxOrphans + 1].header))

  test "sibling forks: promotes both competing child blocks when shared parent arrives":
    var (chain, genesis, gid) = setupChain()

    let
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
      # Competing sibling blocks both parented by B1 at different slots
      b2a = childBlock(b1.header, id1, SlotNumber(2), [])
      id2a = blockId(b2a.header)
      b2b = childBlock(b1.header, id1, SlotNumber(3), [])
      id2b = blockId(b2b.header)

    # Ingest both siblings as orphans
    check chain.tryApplyBlock(b2a).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.tryApplyBlock(b2b).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.orphanPool.len == 2
    check chain.orphanPool.hasOrphan(id2a)
    check chain.orphanPool.hasOrphan(id2b)

    # Ingest parent B1 -> resolves both branches
    check chain.tryApplyBlock(b1).isOk
    check chain.localTree.hasBlock(id1)
    check chain.localTree.hasBlock(id2a)
    check chain.localTree.hasBlock(id2b)
    check chain.orphanPool.len == 0

  test "branching tree cascade: resolves multi-branch orphan tree when root arrives":
    var (chain, genesis, gid) = setupChain()

    let
      # Tree structure:
      #            ┌── B2a (slot 2) ── B3a (slot 4)
      # B1 (slot 1)┤
      #            └── B2b (slot 3) ── B3b (slot 5)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
      b2a = childBlock(b1.header, id1, SlotNumber(2), [])
      id2a = blockId(b2a.header)
      b3a = childBlock(b2a.header, id2a, SlotNumber(4), [])
      id3a = blockId(b3a.header)
      b2b = childBlock(b1.header, id1, SlotNumber(3), [])
      id2b = blockId(b2b.header)
      b3b = childBlock(b2b.header, id2b, SlotNumber(5), [])
      id3b = blockId(b3b.header)

    # Ingest entire orphan tree in reverse / mixed order
    check chain.tryApplyBlock(b3b).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.tryApplyBlock(b3a).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.tryApplyBlock(b2b).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.tryApplyBlock(b2a).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.orphanPool.len == 4

    # Ingest root B1 -> all 4 orphan descendants across both branches are promoted
    check chain.tryApplyBlock(b1).isOk
    check chain.localTree.hasBlock(id1)
    check chain.localTree.hasBlock(id2a)
    check chain.localTree.hasBlock(id3a)
    check chain.localTree.hasBlock(id2b)
    check chain.localTree.hasBlock(id3b)
    check chain.orphanPool.len == 0

  test "dangling sub-tree pruning: invalid promoted orphan purges all waiting descendants":
    var (chain, genesis, gid) = setupChain()

    let
      b1 = childBlock(genesis.header, gid, SlotNumber(2), [])
      id1 = blockId(b1.header)
      # b2 has slot 2 (equal to parent b1 slot 2): passes stateless validateBlock,
      # but fails tree admission (canExtend) on promotion because slot is not > parent.slot
      b2 = childBlock(b1.header, id1, SlotNumber(2), [])
      id2 = blockId(b2.header)
      b3 = childBlock(b2.header, id2, SlotNumber(3), [])
      id3 = blockId(b3.header)
      b4 = childBlock(b3.header, id3, SlotNumber(4), [])
      id4 = blockId(b4.header)

    # Ingest b4, b3, b2 as orphans
    check chain.tryApplyBlock(b4).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.tryApplyBlock(b3).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.tryApplyBlock(b2).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.orphanPool.len == 3

    # Ingest parent b1 -> triggers promotion of b2, which fails state validation.
    # Its descendants b3 and b4 must be pruned immediately.
    check chain.tryApplyBlock(b1).isOk
    check chain.localTree.hasBlock(id1)
    check not chain.localTree.hasBlock(id2)
    check not chain.localTree.hasBlock(id3)
    check not chain.localTree.hasBlock(id4)
    # The pool must have no dangling dead descendants remaining
    check chain.orphanPool.len == 0

  test "orphan branching off unfinalized fork below LIB is rejected immediately":
    var (chain, genesis, gid) = setupChain()

    let
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
      b2a = childBlock(b1.header, id1, SlotNumber(2), [])
      id2a = blockId(b2a.header)
      b2b = childBlock(b1.header, id1, SlotNumber(3), [])
      id2b = blockId(b2b.header)
      b3a = childBlock(b2a.header, id2a, SlotNumber(4), [])

    # Apply b1, b2a, b2b, b3a to tree
    check chain.tryApplyBlock(b1).isOk
    check chain.tryApplyBlock(b2a).isOk
    check chain.tryApplyBlock(b2b).isOk
    check chain.tryApplyBlock(b3a).isOk

    # Finalize branch A at height 2 (B_imm = b2a)
    chain.localTree.latestImmutableHeight = 2
    check chain.localTree.latestImmutableBlockId == id2a

    # Ingest orphan branching off b2b (which violates LIB b2a)
    let
      uncommittedParent = childBlock(b2b.header, id2b, SlotNumber(6), [])

    # First buffer uncommittedParent: parent b2b is in localTree, but not a descendant of b2a (LIB).
    # uncommittedParent fails canDescendFromImmutable and is rejected immediately.
    check chain.tryApplyBlock(uncommittedParent).error.kind == BlockApplyErrorKind.UnviableFork
    check chain.orphanPool.len == 0

  test "orphan with invalid stateless transaction is rejected and not buffered":
    var (chain, genesis, _) = setupChain()

    let baseTx = validSignedTxWithOps(1, 1)
    var badTx = baseTx.signedTx
    badTx.opProofs = @[] # MismatchedOpProofCount

    let missingParentId = exampleBlockId(99)
    let orphan = childBlock(
      genesis.header, missingParentId, SlotNumber(2),
      [ValidSignedMantleTx(signedTx: badTx, hash: baseTx.hash)])

    let applyRes = chain.tryApplyBlock(orphan)
    check applyRes.isErr
    check applyRes.error.kind == BlockApplyErrorKind.StatelessTxRejected
    check chain.orphanPool.len == 0

  test "orphan cascade triggering a reorg restores mempool transactions from abandoned branch":
    var (chain, genesis, gid) = setupChain(securityParam = 1)

    let txA = minimalValidSignedTx()
    check chain.mempool.add(txA, SlotNumber(1))
    check chain.mempool.len == 1

    # Branch A: block a1 with txA
    let a1 = childBlock(genesis.header, gid, SlotNumber(1), [txA])
    let resA1 = chain.tryApplyBlock(a1)
    check resA1.isOk
    check chain.localTree.localTipId == blockId(a1.header)
    check chain.mempool.len == 0 # Pruned on block commit

    # Branch B: blocks b1 -> b2 -> b3 (heavier/taller branch)
    let b1 = childBlock(genesis.header, gid, SlotNumber(2), [])
    let id1 = blockId(b1.header)
    let b2 = childBlock(b1.header, id1, SlotNumber(3), [])
    let id2 = blockId(b2.header)
    let b3 = childBlock(b2.header, id2, SlotNumber(4), [])
    let id3 = blockId(b3.header)

    # Ingest b3 and b2 as orphans
    check chain.tryApplyBlock(b3).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.tryApplyBlock(b2).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.orphanPool.len == 2

    # Ingest root b1 -> cascade promotes b2 and b3, triggering a reorg from a1 to b3
    check chain.tryApplyBlock(b1).isOk
    check chain.localTree.localTipId == id3
    check chain.orphanPool.len == 0
    # txA from abandoned branch A is restored to mempool
    check chain.mempool.len == 1
    # LIB advanced to b2 (height 3 - securityParam 1 = 2)
    check chain.localTree.latestImmutableBlockId == id2

  test "orphan pool prunes orphans whose ancestry cannot descend from newly advanced LIB":
    var (chain, genesis, gid) = setupChain(securityParam = 1)

    # Unfinalized fork block f1
    let f1 = childBlock(genesis.header, gid, SlotNumber(1), [])
    let idF1 = blockId(f1.header)
    check chain.tryApplyBlock(f1).isOk

    # Orphan o2 extends unknown block o1 which extends f1
    let o1 = childBlock(f1.header, idF1, SlotNumber(2), [])
    let idO1 = blockId(o1.header)
    let o2 = childBlock(o1.header, idO1, SlotNumber(3), [])
    check chain.tryApplyBlock(o2).error.kind == BlockApplyErrorKind.OrphanBuffered
    check chain.orphanPool.len == 1

    # Canonical chain extends on competing branch A: a1 -> a2 -> a3 -> a4
    let a1 = childBlock(genesis.header, gid, SlotNumber(2), [])
    let idA1 = blockId(a1.header)
    let a2 = childBlock(a1.header, idA1, SlotNumber(4), [])
    let idA2 = blockId(a2.header)
    let a3 = childBlock(a2.header, idA2, SlotNumber(5), [])
    let idA3 = blockId(a3.header)
    let a4 = childBlock(a3.header, idA3, SlotNumber(6), [])

    check chain.tryApplyBlock(a1).isOk
    check chain.tryApplyBlock(a2).isOk
    check chain.tryApplyBlock(a3).isOk
    # Applying a4 advances LIB to a3 (height 4 - 1 = 3), pruning fork f1 (height 1)
    check chain.tryApplyBlock(a4).isOk
    check chain.localTree.latestImmutableBlockId == idA3

    # Orphan o2 had slot 3 <= LIB slot 5, so pruneIncompatibleWithImmutable pruned it from orphanPool on LIB update!
    check chain.orphanPool.len == 0
