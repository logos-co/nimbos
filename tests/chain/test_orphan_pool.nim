# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  results,
  ../logos_chain/sync/helpers,
  ../../logos_chain/core/types,
  ../../logos_chain/core/local_tree,
  ../../logos_chain/chain/orphan_pool

converter toAdmittedBlock(b: Block): AdmittedBlock =
  AdmittedBlock(b)

suite "chain/orphan_pool":
  test "empty pool properties":
    let pool = OrphanPool()
    check pool.len == 0
    check not pool.hasOrphan(default(BlockId))
    check pool.getOrphan(default(BlockId)).isNone
    check pool.takeChildren(default(BlockId)).len == 0

  test "addOrphan and getOrphan":
    let pool = OrphanPool()
    let parentId = exampleBlockId(1)
    let blk = Block(
      header: Header(
        slot: 1,
        parentBlock: parentId,
      )
    )
    let bId = blockId(blk.header)
    let dupBlk = blk
    check pool.addOrphan(blk)
    check pool.len == 1
    check pool.hasOrphan(bId)
    check pool.getOrphan(bId).isSome
    check pool.getOrphan(bId).get().header.slot == 1

    # duplicate add returns false and does not change pool len
    check not pool.addOrphan(dupBlk)
    check pool.len == 1

  test "takeChildren removes and returns waiting children":
    let pool = OrphanPool()
    let parentId = exampleBlockId(1)
    let child1 = Block(header: Header(slot: 1, parentBlock: parentId))
    let child2 = Block(header: Header(slot: 2, parentBlock: parentId))
    let c1Id = blockId(child1.header)
    let c2Id = blockId(child2.header)

    check pool.addOrphan(child1)
    check pool.addOrphan(child2)
    check pool.len == 2

    let children = pool.takeChildren(parentId)
    check children.len == 2
    check pool.len == 0
    check not pool.hasOrphan(c1Id)
    check not pool.hasOrphan(c2Id)

    # Taking again returns empty sequence
    check pool.takeChildren(parentId).len == 0

  test "removeOrphan removes orphan and cleans up parent mapping":
    let pool = OrphanPool()
    let parentId = exampleBlockId(1)
    let child1 = Block(header: Header(slot: 1, parentBlock: parentId))
    let child2 = Block(header: Header(slot: 2, parentBlock: parentId))
    let c1Id = blockId(child1.header)
    let c2Id = blockId(child2.header)

    check pool.addOrphan(child1)
    check pool.addOrphan(child2)
    check pool.len == 2

    pool.removeOrphan(c1Id)
    check pool.len == 1
    check not pool.hasOrphan(c1Id)

    let remaining = pool.takeChildren(parentId)
    check remaining.len == 1
    check blockId(remaining[0].header) == c2Id

  test "maxOrphans capacity eviction (FIFO)":
    let pool = OrphanPool()
    let p0 = exampleBlockId(1)
    var blocks: seq[Block]
    var ids: seq[BlockId]
    for i in 1 .. MaxOrphans + 1:
      let blk = Block(header: Header(slot: uint64(i), parentBlock: p0))
      ids.add(blockId(blk.header))
      blocks.add(blk)

    for i in 0 ..< MaxOrphans:
      check pool.addOrphan(blocks[i])
    check pool.len == MaxOrphans

    # Adding the next block should evict the oldest (blocks[0])
    check pool.addOrphan(blocks[MaxOrphans])
    check pool.len == MaxOrphans
    check not pool.hasOrphan(ids[0])
    check pool.hasOrphan(ids[1])
    check pool.hasOrphan(ids[MaxOrphans])

    let children = pool.takeChildren(p0)
    check children.len == MaxOrphans

  test "lazy eviction skips already-resolved orphans in deque":
    let pool = OrphanPool()
    let p0 = exampleBlockId(1)
    let p1 = exampleBlockId(2)
    var blocks: seq[Block]
    var ids: seq[BlockId]
    for i in 1 .. MaxOrphans + 3:
      let parent = if i <= 2: p0 else: p1
      let blk = Block(header: Header(slot: uint64(i), parentBlock: parent))
      ids.add(blockId(blk.header))
      blocks.add(blk)

    for i in 0 ..< MaxOrphans:
      check pool.addOrphan(blocks[i])
    check pool.len == MaxOrphans

    # Resolve b1 and b2 (indices 0 and 1) via takeChildren (leaving their IDs in arrivalOrder lazily)
    let p0Children = pool.takeChildren(p0)
    check p0Children.len == 2
    check pool.len == MaxOrphans - 2

    # Add 2 more -> pool len becomes MaxOrphans
    check pool.addOrphan(blocks[MaxOrphans])
    check pool.addOrphan(blocks[MaxOrphans + 1])
    check pool.len == MaxOrphans

    # Add 1 more -> capacity reached; eviction must skip stale b1 and b2 from deque and evict b3 (index 2)
    check pool.addOrphan(blocks[MaxOrphans + 2])
    check pool.len == MaxOrphans
    check not pool.hasOrphan(ids[2]) # b3 was evicted
    check pool.hasOrphan(ids[3])
    check pool.hasOrphan(ids[MaxOrphans + 2])

  test "re-ingesting an evicted orphan succeeds":
    let pool = OrphanPool()
    let p0 = exampleBlockId(1)
    var blocks: seq[Block]
    var ids: seq[BlockId]
    for i in 1 .. MaxOrphans + 1:
      let blk = Block(header: Header(slot: uint64(i), parentBlock: p0))
      ids.add(blockId(blk.header))
      blocks.add(blk)

    let b0Copy = blocks[0]

    for i in 0 ..< MaxOrphans:
      check pool.addOrphan(blocks[i])
    check pool.len == MaxOrphans

    # blocks[MaxOrphans] evicts blocks[0]
    check pool.addOrphan(blocks[MaxOrphans])
    check not pool.hasOrphan(ids[0])

    # Re-ingesting b0Copy should now succeed and evict blocks[1]
    check pool.addOrphan(b0Copy)
    check pool.hasOrphan(ids[0])
    check not pool.hasOrphan(ids[1])
    check pool.hasOrphan(ids[MaxOrphans])

  test "structural invariants: bidirectional mapping consistency across mixed operations":
    let pool = OrphanPool()
    let p0 = exampleBlockId(1)
    let p1 = exampleBlockId(2)

    # Multiple children sharing same parent (siblings)
    let b1 = Block(header: Header(slot: 1, parentBlock: p0))
    let b2 = Block(header: Header(slot: 2, parentBlock: p0))
    let b3 = Block(header: Header(slot: 3, parentBlock: p1))
    let b4 = Block(header: Header(slot: 4, parentBlock: p1))
    let b1Id = blockId(b1.header)
    let b2Id = blockId(b2.header)
    let b3Id = blockId(b3.header)
    let b4Id = blockId(b4.header)

    check pool.addOrphan(b1)
    check pool.addOrphan(b2)
    check pool.addOrphan(b3)
    check pool.addOrphan(b4)
    check pool.len == 4

    # Remove one sibling explicitly
    pool.removeOrphan(b1Id)
    check pool.len == 3
    check not pool.hasOrphan(b1Id)
    check pool.hasOrphan(b2Id)

    # Taking children of p0 should now return only b2 and delete p0 from index
    let p0Children = pool.takeChildren(p0)
    check p0Children.len == 1
    check blockId(p0Children[0].header) == b2Id
    check pool.takeChildren(p0).len == 0

    # Taking children of p1 returns both b3 and b4
    let p1Children = pool.takeChildren(p1)
    check p1Children.len == 2
    check blockId(p1Children[0].header) == b3Id
    check blockId(p1Children[1].header) == b4Id
    check pool.len == 0
    check pool.takeChildren(p1).len == 0

  test "adversarial churn: addOrphan never rejects novel blocks under heavy stale deque churn":
    let pool = OrphanPool()
    # Perform 50 rounds of interleaved add, capacity evictions, and stale resolutions
    for round in 1 .. 50:
      let parent = exampleBlockId(byte(round))
      for slot in 1 .. 3:
        let blk = Block(header: Header(slot: uint64(round * 10 + slot), parentBlock: parent))
        # addOrphan must ALWAYS succeed on novel blocks (never fail due to stale queue entries)
        check pool.addOrphan(blk)
        # Capacity invariant strictly enforced
        check pool.len <= MaxOrphans
      if round mod 2 == 0:
        discard pool.takeChildren(parent)
        check pool.len <= MaxOrphans

  test "pruneIncompatibleWithImmutable removes orphans incompatible with advancing LIB":
    let pool = OrphanPool()
    let genesis = Block(header: Header(slot: 0))
    let tree = newLocalTree(genesis, securityParam = 1'u64)
    let gid = blockId(genesis.header)

    let b1 = Block(header: Header(slot: 1, parentBlock: gid))
    let id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)

    let b2 = Block(header: Header(slot: 2, parentBlock: id1))
    check tree.addBlockToTree(b2)
    # LIB advances to b1 (height 2 - 1 = 1, slot 1)
    discard tree.tryUpdateLib()
    check tree.latestImmutableBlockId == id1

    # Orphan o1 has slot 1 <= LIB slot 1 (incompatible)
    let o1 = Block(header: Header(slot: 1, parentBlock: exampleBlockId(99)))
    let o1Id = blockId(o1.header)
    # Orphan o2 has slot 3 > LIB slot 1 (compatible)
    let o2 = Block(header: Header(slot: 3, parentBlock: exampleBlockId(99)))
    let o2Id = blockId(o2.header)

    check pool.addOrphan(o1)
    check pool.addOrphan(o2)
    check pool.len == 2

    pool.pruneIncompatibleWithImmutable(tree)
    check pool.len == 1
    check not pool.hasOrphan(o1Id)
    check pool.hasOrphan(o2Id)

  test "pruneDescendants purges entire descendant subtree":
    let pool = OrphanPool()
    let
      rootId = exampleBlockId(1)
      c1 = Block(header: Header(slot: 2, parentBlock: rootId))
      c1Id = blockId(c1.header)
      d1 = Block(header: Header(slot: 3, parentBlock: c1Id))
      d1Id = blockId(d1.header)
      d2 = Block(header: Header(slot: 4, parentBlock: d1Id))
      d2Id = blockId(d2.header)
      unrelated = Block(header: Header(slot: 2, parentBlock: exampleBlockId(99)))
      unrelatedId = blockId(unrelated.header)

    check pool.addOrphan(c1)
    check pool.addOrphan(d1)
    check pool.addOrphan(d2)
    check pool.addOrphan(unrelated)
    check pool.len == 4

    # Prune descendants of rootId (purges c1 -> d1 -> d2)
    pool.pruneDescendants(rootId)
    check pool.len == 1
    check not pool.hasOrphan(c1Id)
    check not pool.hasOrphan(d1Id)
    check not pool.hasOrphan(d2Id)
    check pool.hasOrphan(unrelatedId)

  test "compactQueue removes stale deque entries":
    let pool = OrphanPool()
    let parent = exampleBlockId(1)
    let b1 = Block(header: Header(slot: 1, parentBlock: parent))
    let b2 = Block(header: Header(slot: 2, parentBlock: parent))
    let b1Id = blockId(b1.header)
    let b2Id = blockId(b2.header)

    check pool.addOrphan(b1)
    check pool.addOrphan(b2)
    check pool.len == 2

    # Remove b1 directly
    pool.removeOrphan(b1Id)
    check pool.len == 1

    # Compacting queue purges b1 from arrivalOrder
    pool.compactQueue()
    check pool.len == 1
    check not pool.hasOrphan(b1Id)
    check pool.hasOrphan(b2Id)
