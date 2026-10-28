# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  ../testutil,
  ../../logos_chain/core/types,
  ../../logos_chain/chain/local_tree

suite "chain/local_tree":
  test "LocalTree.init stores genesis at height 0":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = LocalTree.init(genesis)
    check tree.hasBlock(gid)
    check tree.blockHeight(gid) == Opt.some(0'u64)
    check tree.fetchHeader(gid).get == genesis.header

  test "addBlockToTree extends chain and updates heights and ancestry":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = LocalTree.init(genesis)
      b1 = mkChildValidBlock(genesis.header, gid, 1'u64)
      id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)
    check tree.hasBlock(id1)
    check tree.blockHeight(id1) == Opt.some(1'u64)
    check tree.isAncestor(gid, id1)
    check not tree.isAncestor(id1, gid)
    check tree.isAncestor(gid, gid)

  test "addBlockToTree rejects duplicate id":
    let
      genesis = testGenesisBlock()
      tree = LocalTree.init(genesis)
    check not tree.addBlockToTree(genesis)

  test "addBlockToTree rejects zero parent and unknown parent":
    let
      genesis = testGenesisBlock()
      tree = LocalTree.init(genesis)
    var fakeParent: BlockId
    for i in 0 ..< fakeParent.len:
      fakeParent[i] = byte(i)
    let orphan = mkChildValidBlock(genesis.header, fakeParent, 1'u64)
    check not tree.addBlockToTree(orphan)
    let bad = mkChildValidBlock(genesis.header, default(BlockId), 99'u64)
    check not tree.addBlockToTree(bad)

  test "blockHeight returns none for unknown id":
    let tree = LocalTree.init(testGenesisBlock())
    var unknown: BlockId
    unknown[0] = 1'u8
    check tree.blockHeight(unknown).isNone

  test "ancestorAtHeight walks back on tip branch":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = LocalTree.init(genesis)
      b1 = mkChildValidBlock(genesis.header, gid, 1'u64)
      id1 = blockId(b1.header)
      b2 = mkChildValidBlock(b1.header, id1, 2'u64)
      id2 = blockId(b2.header)
    check tree.addBlockToTree(b1)
    check tree.ancestorAtHeight(id1, 0'u64) == Opt.some(gid)
    check tree.addBlockToTree(b2)
    check tree.ancestorAtHeight(id2, 1'u64) == Opt.some(id1)
    check tree.ancestorAtHeight(id2, 0'u64) == Opt.some(gid)

suite "chain/local_tree (lcaBlockIdAndHeight)":
  test "lcaBlockIdAndHeight of genesis with itself is genesis":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = LocalTree.init(genesis)
    let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, gid, gid).get()
    check lcaId == gid
    check lcaHeight == 0'u64

  test "lcaBlockIdAndHeight on a linear chain (depth and symmetry)":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = LocalTree.init(genesis)
      b1 = mkChildValidBlock(genesis.header, gid, 1'u64)
      id1 = blockId(b1.header)
      b2 = mkChildValidBlock(b1.header, id1, 2'u64)
      id2 = blockId(b2.header)
    check tree.addBlockToTree(b1)
    check tree.addBlockToTree(b2)
    block:
      let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, gid, id2).get()
      check lcaId == gid
      check lcaHeight == 0'u64
    block:
      let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, id1, id2).get()
      check lcaId == id1
      check lcaHeight == 1'u64
    block:
      let (a, _) = lcaBlockIdAndHeight(tree, id2, id1).get()
      let (b, _) = lcaBlockIdAndHeight(tree, id1, id2).get()
      check a == b

  test "lcaBlockIdAndHeight across two children of genesis is genesis":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = LocalTree.init(genesis)
      left1 = mkChildValidBlock(genesis.header, gid, 1'u64)
      left1Id = blockId(left1.header)
      left2 = mkChildValidBlock(left1.header, left1Id, 2'u64)
      left2Id = blockId(left2.header)
      right = mkChildValidBlock(genesis.header, gid, 3'u64)
      rightId = blockId(right.header)
    check tree.addBlockToTree(left1)
    check tree.addBlockToTree(left2)
    check tree.addBlockToTree(right)
    let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, left2Id, rightId).get()
    check lcaId == gid
    check lcaHeight == 0'u64

  test "lcaBlockIdAndHeight returns none if either id is unknown":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = LocalTree.init(genesis)
    var unknown: BlockId
    unknown[0] = 7'u8
    check lcaBlockIdAndHeight(tree, gid, unknown).isNone
    check lcaBlockIdAndHeight(tree, unknown, gid).isNone
    
  test "pruneForks prunes side-branch nodes below finality height":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = LocalTree.init(genesis)
      b1 = mkChildValidBlock(genesis.header, gid, 1'u64)
      id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)
    let
      sideB = mkChildValidBlock(genesis.header, gid, 2'u64)
      idSide = blockId(sideB.header)
    check tree.addBlockToTree(sideB)

    check tree.blocksIdsAtHeight(1'u64).len == 2

    # Advance immutable block to b1 by adding b2 (height 2)
    let b2 = mkChildValidBlock(b1.header, id1, 3'u64)
    check tree.addBlockToTree(b2)
    let pruned = tree.pruneForks(id1, oldImmHeight = 0'u64, tipHeight = 2'u64)
    check idSide in pruned

    # sideB is height 1, not ancestor of b2 -> pruned!
    check not tree.hasBlock(idSide)
    check tree.hasBlock(gid)
    check tree.hasBlock(id1)

    # Single-element invariant for finalized height
    check tree.blocksIdsAtHeight(1'u64).len == 1
    check tree.blocksIdsAtHeight(1'u64)[0] == id1

  test "pruneForks handles linear fast-path, cascades upward orphan pruning, and terminates early":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = LocalTree.init(genesis)

      # 1. Build canonical chain up to height 3, verifying fast-path on linear chain
      b1 = mkChildValidBlock(genesis.header, gid, 1'u64)
      id1 = blockId(b1.header)
      b2 = mkChildValidBlock(b1.header, id1, 2'u64)
      id2 = blockId(b2.header)
      b3 = mkChildValidBlock(b2.header, id2, 3'u64)
      id3 = blockId(b3.header)

    check tree.addBlockToTree(b1)
    check tree.pruneForks(id1, oldImmHeight = 0'u64, tipHeight = 1'u64).len == 0 # Fast-path
    check tree.addBlockToTree(b2)
    check tree.pruneForks(id2, oldImmHeight = 1'u64, tipHeight = 2'u64).len == 0 # Fast-path
    check tree.addBlockToTree(b3)
    check tree.pruneForks(id3, oldImmHeight = 2'u64, tipHeight = 3'u64).len == 0 # Fast-path

    # 2. Build competing fork branching off b1 (height 1):
    #    f2 at height 2, f3 at height 3
    let
      f2 = mkChildValidBlock(b1.header, id1, 10'u64)
      idF2 = blockId(f2.header)
      f3 = mkChildValidBlock(f2.header, idF2, 11'u64)
      idF3 = blockId(f3.header)

    check tree.addBlockToTree(f2)
    check tree.addBlockToTree(f3)

    # Before LIB update: all blocks are in the tree
    check tree.hasBlock(idF2)
    check tree.hasBlock(idF3)
    check tree.blocksIdsAtHeight(3'u64).len == 2

    # 3. Add canonical b4, b5 (tip is now height 5)
    let
      b4 = mkChildValidBlock(b3.header, id3, 4'u64)
      id4 = blockId(b4.header)
      b5 = mkChildValidBlock(b4.header, id4, 5'u64)
      id5 = blockId(b5.header)
    check tree.addBlockToTree(b4)
    check tree.addBlockToTree(b5)

    # 4. Trigger LIB update:
    #    immHeight = 5 - 2 = 3 (new LIB is b3 at height 3).
    #    - Pass 1 prunes f2 at height 2.
    #    - Pass 2 prunes f3 at height 3 (missing parent f2).
    #    - Pass 2 checks height 4 (only canonical b4 exists, ids.len == 1) and breaks early!
    let pruned = tree.pruneForks(id3, oldImmHeight = 0'u64, tipHeight = 5'u64)
    check idF2 in pruned
    check idF3 in pruned

    # Neither f2 nor the floating island f3 should remain in the tree
    check not tree.hasBlock(idF2)
    check not tree.hasBlock(idF3)

    # Canonical blocks at all heights are intact
    for id in [gid, id1, id2, id3, id4, id5]:
      check tree.hasBlock(id)
    check tree.blocksIdsAtHeight(3'u64) == @[id3]

suite "chain/local_tree (countChainDensity)":
  test "counts only blocks within the half-open window (lcaSlot, lcaSlot + densitySlotWindow]":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = LocalTree.init(genesis)

      # Genesis is at slot 0
      # LCA block at slot 10
      b1 = mkChildValidBlock(genesis.header, gid, slot = 10'u64)
      id1 = blockId(b1.header)

      # Chain A: slots 15, 25, 45
      b2 = mkChildValidBlock(b1.header, id1, slot = 15'u64)
      id2 = blockId(b2.header)
      b3 = mkChildValidBlock(b2.header, id2, slot = 25'u64)
      id3 = blockId(b3.header)
      b4 = mkChildValidBlock(b3.header, id3, slot = 45'u64)
      id4 = blockId(b4.header)

    check:
      tree.addBlockToTree(b1)
      tree.addBlockToTree(b2)
      tree.addBlockToTree(b3)
      tree.addBlockToTree(b4)

      # Window of 2 slots from slot 10 -> interval (10, 12]
      # All blocks are outside (> 12) -> count = 0
      countChainDensity(tree, id4, lcaSlot = 10'u64, lcaHeight = 1'u64, densitySlotWindow = 2'u64) == 0'u64

      # Window of 5 slots from slot 10 -> interval (10, 15]
      # Blocks in window: slot 15 -> count = 1
      countChainDensity(tree, id4, lcaSlot = 10'u64, lcaHeight = 1'u64, densitySlotWindow = 5'u64) == 1'u64

      # Window of 20 slots starting from LCA slot 10 -> interval (10, 30]
      # Blocks in window: slot 15, slot 25 -> count = 2
      # Block at slot 45 is outside (> 30) -> not counted
      # Block at slot 10 is LCA (<= 10) -> not counted
      countChainDensity(tree, id4, lcaSlot = 10'u64, lcaHeight = 1'u64, densitySlotWindow = 20'u64) == 2'u64

      # Window of 40 slots from slot 10 -> interval (10, 50]
      # Blocks in window: slot 15, 25, 45 -> count = 3
      countChainDensity(tree, id4, lcaSlot = 10'u64, lcaHeight = 1'u64, densitySlotWindow = 40'u64) == 3'u64

{.pop.}
