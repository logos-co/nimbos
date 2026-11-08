# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  ../testutil,
  ../../logos_chain/core/types,
  ../../logos_chain/consensus/consensus_state,
  ../../logos_chain/chain/orphan_pool

suite "chain/orphan_pool":
  test "empty pool properties":
    let pool = OrphanPool()
    check:
      pool.len == 0
      not pool.hasOrphan(default(BlockId))
      pool.takeChildren(default(BlockId)).len == 0

  test "addOrphan buffers block":
    let
      pool = OrphanPool()
      parentId = exampleBlockId(1)
      blk = mkAdmittedBlock(1, parentId)
      bId = blockId(blk.header)
      dupBlk = blk
    check:
      pool.addOrphan(blk)
      pool.len == 1
      pool.hasOrphan(bId)
      not pool.addOrphan(dupBlk)
      pool.len == 1

  test "takeChildren removes and returns waiting children":
    let
      pool = OrphanPool()
      parentId = exampleBlockId(1)
      child1 = mkAdmittedBlock(1, parentId)
      child2 = mkAdmittedBlock(2, parentId)
      c1Id = blockId(child1.header)
      c2Id = blockId(child2.header)

    check:
      pool.addOrphan(child1)
      pool.addOrphan(child2)
      pool.len == 2

    let children = pool.takeChildren(parentId)
    check:
      children.len == 2
      pool.len == 0
      not pool.hasOrphan(c1Id)
      not pool.hasOrphan(c2Id)

    # Taking again returns empty sequence
    check pool.takeChildren(parentId).len == 0

  test "removeOrphan removes orphan and cleans up parent mapping":
    let
      pool = OrphanPool()
      parentId = exampleBlockId(1)
      child1 = mkAdmittedBlock(1, parentId)
      child2 = mkAdmittedBlock(2, parentId)
      c1Id = blockId(child1.header)
      c2Id = blockId(child2.header)

    check:
      pool.addOrphan(child1)
      pool.addOrphan(child2)
      pool.len == 2

    pool.removeOrphan(c1Id)
    check:
      pool.len == 1
      not pool.hasOrphan(c1Id)

    let remaining = pool.takeChildren(parentId)
    check:
      remaining.len == 1
      blockId(remaining[0].header) == c2Id

  test "maxOrphans capacity eviction (FIFO)":
    let
      pool = OrphanPool()
      p0 = exampleBlockId(1)
    var
      blocks: seq[AdmittedBlock]
      ids: seq[BlockId]
    for i in 1 .. MaxOrphans + 1:
      let blk = mkAdmittedBlock(uint64(i), p0)
      ids.add(blockId(blk.header))
      blocks.add(blk)

    for i in 0 ..< MaxOrphans:
      check pool.addOrphan(blocks[i])
    check:
      pool.len == MaxOrphans
      # Adding the next block should evict the oldest (blocks[0])
      pool.addOrphan(blocks[MaxOrphans])
      pool.len == MaxOrphans
      not pool.hasOrphan(ids[0])
      pool.hasOrphan(ids[1])
      pool.hasOrphan(ids[MaxOrphans])

    let children = pool.takeChildren(p0)
    check children.len == MaxOrphans

  test "lazy eviction skips already-resolved orphans in deque":
    let
      pool = OrphanPool()
      p0 = exampleBlockId(1)
      p1 = exampleBlockId(2)
    var
      blocks: seq[AdmittedBlock]
      ids: seq[BlockId]
    for i in 1 .. MaxOrphans + 3:
      let
        parent = if i <= 2: p0 else: p1
        blk = mkAdmittedBlock(uint64(i), parent)
      ids.add(blockId(blk.header))
      blocks.add(blk)

    for i in 0 ..< MaxOrphans:
      check pool.addOrphan(blocks[i])
    check pool.len == MaxOrphans

    # Resolve b1 and b2 (indices 0 and 1) via takeChildren (leaving their IDs in arrivalOrder lazily)
    let p0Children = pool.takeChildren(p0)
    check:
      p0Children.len == 2
      pool.len == MaxOrphans - 2
      # Add 2 more -> pool len becomes MaxOrphans
      pool.addOrphan(blocks[MaxOrphans])
      pool.addOrphan(blocks[MaxOrphans + 1])
      pool.len == MaxOrphans
      # Add 1 more -> capacity reached; eviction must skip stale b1 and b2 from deque and evict b3 (index 2)
      pool.addOrphan(blocks[MaxOrphans + 2])
      pool.len == MaxOrphans
      not pool.hasOrphan(ids[2]) # b3 was evicted
      pool.hasOrphan(ids[3])
      pool.hasOrphan(ids[MaxOrphans + 2])

  test "re-ingesting an evicted orphan succeeds":
    let
      pool = OrphanPool()
      p0 = exampleBlockId(1)
    var
      blocks: seq[AdmittedBlock]
      ids: seq[BlockId]
    for i in 1 .. MaxOrphans + 1:
      let blk = mkAdmittedBlock(uint64(i), p0)
      ids.add(blockId(blk.header))
      blocks.add(blk)

    let b0Copy = blocks[0]

    for i in 0 ..< MaxOrphans:
      check pool.addOrphan(blocks[i])
    check:
      pool.len == MaxOrphans
      # blocks[MaxOrphans] evicts blocks[0]
      pool.addOrphan(blocks[MaxOrphans])
      not pool.hasOrphan(ids[0])
      # Re-ingesting b0Copy should now succeed and evict blocks[1]
      pool.addOrphan(b0Copy)
      pool.hasOrphan(ids[0])
      not pool.hasOrphan(ids[1])
      pool.hasOrphan(ids[MaxOrphans])

  test "structural invariants: bidirectional mapping consistency across mixed operations":
    let
      pool = OrphanPool()
      p0 = exampleBlockId(1)
      p1 = exampleBlockId(2)
      # Multiple children sharing same parent (siblings)
      b1 = mkAdmittedBlock(1, p0)
      b2 = mkAdmittedBlock(2, p0)
      b3 = mkAdmittedBlock(3, p1)
      b4 = mkAdmittedBlock(4, p1)
      b1Id = blockId(b1.header)
      b2Id = blockId(b2.header)
      b3Id = blockId(b3.header)
      b4Id = blockId(b4.header)

    check:
      pool.addOrphan(b1)
      pool.addOrphan(b2)
      pool.addOrphan(b3)
      pool.addOrphan(b4)
      pool.len == 4

    # Remove one sibling explicitly
    pool.removeOrphan(b1Id)
    check:
      pool.len == 3
      not pool.hasOrphan(b1Id)
      pool.hasOrphan(b2Id)

    # Taking children of p0 should now return only b2 and delete p0 from index
    let p0Children = pool.takeChildren(p0)
    check:
      p0Children.len == 1
      blockId(p0Children[0].header) == b2Id
      pool.takeChildren(p0).len == 0

    # Taking children of p1 returns both b3 and b4
    let p1Children = pool.takeChildren(p1)
    check:
      p1Children.len == 2
      blockId(p1Children[0].header) == b3Id
      blockId(p1Children[1].header) == b4Id
      pool.len == 0
      pool.takeChildren(p1).len == 0

  test "adversarial churn: addOrphan never rejects novel blocks under heavy stale deque churn":
    let pool = OrphanPool()
    # Perform 50 rounds of interleaved add, capacity evictions, and stale resolutions
    for round in 1 .. 50:
      let parent = exampleBlockId(byte(round))
      for slot in 1 .. 3:
        let blk = mkAdmittedBlock(uint64(round * 10 + slot), parent)
        check:
          # addOrphan must ALWAYS succeed on novel blocks (never fail due to stale queue entries)
          pool.addOrphan(blk)
          # Capacity invariant strictly enforced
          pool.len <= MaxOrphans
      if round mod 2 == 0:
        discard pool.takeChildren(parent)
        check pool.len <= MaxOrphans

  test "pruneIncompatibleWithImmutable removes orphans incompatible with advancing LIB":
    let
      pool = OrphanPool()
      genesis = testGenesisBlock()
      cs = ConsensusState.init(
        genesis, securityParam = 1'u64, densitySlotWindow = 100'u64, forkChoiceRule = ForkChoiceRule.Bootstrap
      )
      gid = blockId(genesis.header)
      b1 = mkChildValidBlock(genesis.header, gid, SlotNumber(1))
      id1 = blockId(b1.header)
    check cs.addBlockAndTryUpdateTip(b1)

    let b2 = mkChildValidBlock(b1.header, id1, SlotNumber(2))
    check cs.addBlockAndTryUpdateTip(b2)
    # LIB advances to b1 (height 2 - 1 = 1, slot 1)
    discard cs.tryUpdateLib()
    check cs.latestImmutableId == id1

    # Orphan o1 has slot 1 <= LIB slot 1 (incompatible)
    let
      o1 = mkAdmittedBlock(1, exampleBlockId(99))
      o1Id = blockId(o1.header)
      # Orphan o2 has slot 3 > LIB slot 1 (compatible)
      o2 = mkAdmittedBlock(3, exampleBlockId(99))
      o2Id = blockId(o2.header)

    check:
      pool.addOrphan(o1)
      pool.addOrphan(o2)
      pool.len == 2

    pool.pruneIncompatibleWithImmutable(cs)
    check:
      pool.len == 1
      not pool.hasOrphan(o1Id)
      pool.hasOrphan(o2Id)

  test "pruneDescendants purges entire descendant subtree":
    let
      pool = OrphanPool()
      rootId = exampleBlockId(1)
      c1 = mkAdmittedBlock(2, rootId)
      c1Id = blockId(c1.header)
      d1 = mkAdmittedBlock(3, c1Id)
      d1Id = blockId(d1.header)
      d2 = mkAdmittedBlock(4, d1Id)
      d2Id = blockId(d2.header)
      unrelated = mkAdmittedBlock(2, exampleBlockId(99))
      unrelatedId = blockId(unrelated.header)

    check:
      pool.addOrphan(c1)
      pool.addOrphan(d1)
      pool.addOrphan(d2)
      pool.addOrphan(unrelated)
      pool.len == 4

    # Prune descendants of rootId (purges c1 -> d1 -> d2)
    pool.pruneDescendants(rootId)
    check:
      pool.len == 1
      not pool.hasOrphan(c1Id)
      not pool.hasOrphan(d1Id)
      not pool.hasOrphan(d2Id)
      pool.hasOrphan(unrelatedId)

  test "compactQueue removes stale deque entries":
    let
      pool = OrphanPool()
      parent = exampleBlockId(1)
      b1 = mkAdmittedBlock(1, parent)
      b2 = mkAdmittedBlock(2, parent)
      b1Id = blockId(b1.header)
      b2Id = blockId(b2.header)

    check:
      pool.addOrphan(b1)
      pool.addOrphan(b2)
      pool.len == 2

    # Remove b1 directly
    pool.removeOrphan(b1Id)
    check pool.len == 1

    # Compacting queue purges b1 from arrivalOrder
    pool.compactQueue()
    check:
      pool.len == 1
      not pool.hasOrphan(b1Id)
      pool.hasOrphan(b2Id)

{.pop.}
