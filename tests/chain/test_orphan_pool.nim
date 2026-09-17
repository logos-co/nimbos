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
    let blk = ValidBlock(
      Block(
        header: Header(
          slot: 1,
          parentBlock: parentId,
        )
      )
    )
    let bId = blockId(blk.header)
    check pool.addOrphan(blk, blk.header.slot)
    check pool.len == 1
    check pool.hasOrphan(bId)
    check pool.getOrphan(bId).isSome
    check pool.getOrphan(bId).get().header.slot == 1

    # duplicate add returns false and does not change pool len
    check not pool.addOrphan(blk, blk.header.slot)
    check pool.len == 1

  test "takeChildren removes and returns waiting children":
    let pool = OrphanPool()
    let parentId = exampleBlockId(1)
    let child1 = ValidBlock(Block(header: Header(slot: 1, parentBlock: parentId)))
    let child2 = ValidBlock(Block(header: Header(slot: 2, parentBlock: parentId)))

    check pool.addOrphan(child1, child1.header.slot)
    check pool.addOrphan(child2, child2.header.slot)
    check pool.len == 2

    let children = pool.takeChildren(parentId)
    check children.len == 2
    check pool.len == 0
    check not pool.hasOrphan(blockId(child1.header))
    check not pool.hasOrphan(blockId(child2.header))

    # Taking again returns empty sequence
    check pool.takeChildren(parentId).len == 0

  test "removeOrphan removes orphan and cleans up parent mapping":
    let pool = OrphanPool()
    let parentId = exampleBlockId(1)
    let child1 = ValidBlock(Block(header: Header(slot: 1, parentBlock: parentId)))
    let child2 = ValidBlock(Block(header: Header(slot: 2, parentBlock: parentId)))

    check pool.addOrphan(child1, child1.header.slot)
    check pool.addOrphan(child2, child2.header.slot)
    check pool.len == 2

    check pool.removeOrphan(blockId(child1.header))
    check pool.len == 1
    check not pool.hasOrphan(blockId(child1.header))

    let remaining = pool.takeChildren(parentId)
    check remaining.len == 1
    check blockId(remaining[0].header) == blockId(child2.header)

  test "maxOrphans capacity eviction (FIFO)":
    let pool = OrphanPool()
    let p0 = exampleBlockId(1)
    var blocks: seq[ValidBlock]
    for i in 1 .. MaxOrphans + 1:
      blocks.add(ValidBlock(Block(header: Header(slot: uint64(i), parentBlock: p0))))

    for i in 0 ..< MaxOrphans:
      check pool.addOrphan(blocks[i], blocks[i].header.slot)
    check pool.len == MaxOrphans

    # Adding the next block should evict the oldest (blocks[0])
    check pool.addOrphan(blocks[MaxOrphans], blocks[MaxOrphans].header.slot)
    check pool.len == MaxOrphans
    check not pool.hasOrphan(blockId(blocks[0].header))
    check pool.hasOrphan(blockId(blocks[1].header))
    check pool.hasOrphan(blockId(blocks[MaxOrphans].header))

    let children = pool.takeChildren(p0)
    check children.len == MaxOrphans

  test "lazy eviction skips already-resolved orphans in deque":
    let pool = OrphanPool()
    let p0 = exampleBlockId(1)
    let p1 = exampleBlockId(2)
    var blocks: seq[ValidBlock]
    for i in 1 .. MaxOrphans + 3:
      let parent = if i <= 2: p0 else: p1
      blocks.add(ValidBlock(Block(header: Header(slot: uint64(i), parentBlock: parent))))

    for i in 0 ..< MaxOrphans:
      check pool.addOrphan(blocks[i], blocks[i].header.slot)
    check pool.len == MaxOrphans

    # Resolve b1 and b2 (indices 0 and 1) via takeChildren (leaving their IDs in arrivalOrder lazily)
    let p0Children = pool.takeChildren(p0)
    check p0Children.len == 2
    check pool.len == MaxOrphans - 2

    # Add 2 more -> pool len becomes MaxOrphans
    check pool.addOrphan(blocks[MaxOrphans], blocks[MaxOrphans].header.slot)
    check pool.addOrphan(blocks[MaxOrphans + 1], blocks[MaxOrphans + 1].header.slot)
    check pool.len == MaxOrphans

    # Add 1 more -> capacity reached; eviction must skip stale b1 and b2 from deque and evict b3 (index 2)
    check pool.addOrphan(blocks[MaxOrphans + 2], blocks[MaxOrphans + 2].header.slot)
    check pool.len == MaxOrphans
    check not pool.hasOrphan(blockId(blocks[2].header)) # b3 was evicted
    check pool.hasOrphan(blockId(blocks[3].header))
    check pool.hasOrphan(blockId(blocks[MaxOrphans + 2].header))

  test "re-ingesting an evicted orphan succeeds":
    let pool = OrphanPool()
    let p0 = exampleBlockId(1)
    var blocks: seq[ValidBlock]
    for i in 1 .. MaxOrphans + 1:
      blocks.add(ValidBlock(Block(header: Header(slot: uint64(i), parentBlock: p0))))

    for i in 0 ..< MaxOrphans:
      check pool.addOrphan(blocks[i], blocks[i].header.slot)
    check pool.len == MaxOrphans

    # blocks[MaxOrphans] evicts blocks[0]
    check pool.addOrphan(blocks[MaxOrphans], blocks[MaxOrphans].header.slot)
    check not pool.hasOrphan(blockId(blocks[0].header))

    # Re-ingesting blocks[0] should now succeed and evict blocks[1]
    check pool.addOrphan(blocks[0], blocks[0].header.slot)
    check pool.hasOrphan(blockId(blocks[0].header))
    check not pool.hasOrphan(blockId(blocks[1].header))
    check pool.hasOrphan(blockId(blocks[MaxOrphans].header))

  test "structural invariants: bidirectional mapping consistency across mixed operations":
    let pool = OrphanPool()
    let p0 = exampleBlockId(1)
    let p1 = exampleBlockId(2)

    # Multiple children sharing same parent (siblings)
    let b1 = ValidBlock(Block(header: Header(slot: 1, parentBlock: p0)))
    let b2 = ValidBlock(Block(header: Header(slot: 2, parentBlock: p0)))
    let b3 = ValidBlock(Block(header: Header(slot: 3, parentBlock: p1)))
    let b4 = ValidBlock(Block(header: Header(slot: 4, parentBlock: p1)))

    check pool.addOrphan(b1, b1.header.slot)
    check pool.addOrphan(b2, b2.header.slot)
    check pool.addOrphan(b3, b3.header.slot)
    check pool.addOrphan(b4, b4.header.slot)
    check pool.len == 4

    # Remove one sibling explicitly
    check pool.removeOrphan(blockId(b1.header))
    check pool.len == 3
    check not pool.hasOrphan(blockId(b1.header))
    check pool.hasOrphan(blockId(b2.header))

    # Taking children of p0 should now return only b2 and delete p0 from index
    let p0Children = pool.takeChildren(p0)
    check p0Children.len == 1
    check blockId(p0Children[0].header) == blockId(b2.header)
    check pool.takeChildren(p0).len == 0

    # Taking children of p1 returns both b3 and b4
    let p1Children = pool.takeChildren(p1)
    check p1Children.len == 2
    check pool.len == 0
    check pool.takeChildren(p1).len == 0

  test "adversarial churn: addOrphan never rejects novel blocks under heavy stale deque churn":
    let pool = OrphanPool()
    # Perform 50 rounds of interleaved add, capacity evictions, and stale resolutions
    for round in 1 .. 50:
      let parent = exampleBlockId(byte(round))
      for slot in 1 .. 3:
        let blk = ValidBlock(Block(header: Header(slot: uint64(round * 10 + slot), parentBlock: parent)))
        # addOrphan must ALWAYS succeed on novel blocks (never fail due to stale queue entries)
        check pool.addOrphan(blk, blk.header.slot)
        # Capacity invariant strictly enforced
        check pool.len <= MaxOrphans
      if round mod 2 == 0:
        discard pool.takeChildren(parent)
        check pool.len <= MaxOrphans

  test "pruneStale removes all orphans older than MaxOrphanSlotAge":
    let pool = OrphanPool()
    let p = exampleBlockId(1)
    let b1 = ValidBlock(Block(header: Header(slot: 5, parentBlock: p)))
    let b2 = ValidBlock(Block(header: Header(slot: 10, parentBlock: p)))
    let b3 = ValidBlock(Block(header: Header(slot: 15, parentBlock: p)))

    check pool.addOrphan(b1, b1.header.slot)
    check pool.addOrphan(b2, b2.header.slot)
    check pool.addOrphan(b3, b3.header.slot)
    check pool.len == 3

    # At currentSlot 2170, threshold is 2170 - 2160 = 10 (should prune b1 with slot 5)
    pool.pruneStale(SlotNumber(2170))
    check pool.len == 2
    check not pool.hasOrphan(blockId(b1.header))
    check pool.hasOrphan(blockId(b2.header))
    check pool.hasOrphan(blockId(b3.header))

    # At currentSlot 2180, threshold is 2180 - 2160 = 20 (should prune b2 and b3)
    pool.pruneStale(SlotNumber(2180))
    check pool.len == 0

  test "pruneIncompatibleWithImmutable removes orphans incompatible with advancing LIB":
    let pool = OrphanPool()
    let genesis = Block(header: Header(slot: 0))
    let tree = newLocalTree(genesis, securityParam = 1'u64)
    let gid = blockId(genesis.header)

    let b1 = Block(header: Header(slot: 1, parentBlock: gid))
    let id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)

    let b2 = Block(header: Header(slot: 2, parentBlock: id1))
    let id2 = blockId(b2.header)
    check tree.addBlockToTree(b2)
    # LIB advances to b1 (height 2 - 1 = 1, slot 1)
    discard tree.tryUpdateLib()
    check tree.latestImmutableBlockId == id1

    # Orphan o1 has slot 1 <= LIB slot 1 (incompatible)
    let o1 = ValidBlock(Block(header: Header(slot: 1, parentBlock: exampleBlockId(99))))
    # Orphan o2 has slot 3 > LIB slot 1 (compatible)
    let o2 = ValidBlock(Block(header: Header(slot: 3, parentBlock: exampleBlockId(99))))

    check pool.addOrphan(o1, o1.header.slot)
    check pool.addOrphan(o2, o2.header.slot)
    check pool.len == 2

    pool.pruneIncompatibleWithImmutable(tree)
    check pool.len == 1
    check not pool.hasOrphan(blockId(o1.header))
    check pool.hasOrphan(blockId(o2.header))

  test "pruneDescendants purges entire descendant subtree":
    let pool = OrphanPool()
    let
      rootId = exampleBlockId(1)
      c1 = ValidBlock(Block(header: Header(slot: 2, parentBlock: rootId)))
      c1Id = blockId(c1.header)
      d1 = ValidBlock(Block(header: Header(slot: 3, parentBlock: c1Id)))
      d1Id = blockId(d1.header)
      d2 = ValidBlock(Block(header: Header(slot: 4, parentBlock: d1Id)))
      unrelated = ValidBlock(Block(header: Header(slot: 2, parentBlock: exampleBlockId(99))))

    check pool.addOrphan(c1, c1.header.slot)
    check pool.addOrphan(d1, d1.header.slot)
    check pool.addOrphan(d2, d2.header.slot)
    check pool.addOrphan(unrelated, unrelated.header.slot)
    check pool.len == 4

    # Prune descendants of rootId (purges c1 -> d1 -> d2)
    pool.pruneDescendants(rootId)
    check pool.len == 1
    check not pool.hasOrphan(c1Id)
    check not pool.hasOrphan(d1Id)
    check not pool.hasOrphan(blockId(d2.header))
    check pool.hasOrphan(blockId(unrelated.header))

  test "addOrphan lazily evicts stale blocks and rejects stale additions":
    let pool = OrphanPool()
    let p = exampleBlockId(1)
    let b1 = ValidBlock(Block(header: Header(slot: 5, parentBlock: p)))
    let b2 = ValidBlock(Block(header: Header(slot: 10, parentBlock: p)))

    check pool.addOrphan(b1, b1.header.slot)
    check pool.addOrphan(b2, b2.header.slot)
    check pool.len == 2

    # Adding b3 with slot 2170: refSlot is 2170, stale threshold is 2170 - 2160 = 10
    # b1 (slot 5) is pruned lazily, b2 (slot 10) and b3 (slot 2170) remain
    let b3 = ValidBlock(Block(header: Header(slot: 2170, parentBlock: p)))
    check pool.addOrphan(b3, b3.header.slot)
    check pool.len == 2
    check not pool.hasOrphan(blockId(b1.header))
    check pool.hasOrphan(blockId(b2.header))
    check pool.hasOrphan(blockId(b3.header))

    # Attempting to add a stale block directly at currentSlot 2170 is rejected (DOA)
    let staleBlock = ValidBlock(Block(header: Header(slot: 8, parentBlock: p)))
    check not pool.addOrphan(staleBlock, currentSlot = SlotNumber(2170))
    check pool.len == 2


