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

func isAncestor(localTree: LocalTree, ancestor, descendant: BlockId): bool =
  if ancestor == descendant:
    return localTree.hasBlock(ancestor)
  var curr = descendant
  while true:
    let hdr = localTree.fetchHeader(curr).valueOr:
      return false
    if hdr.parentBlock == ancestor:
      return true
    curr = hdr.parentBlock

suite "chain/local_tree":
  test "newLocalTree stores genesis as tip at height 0":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
    check:
      tree.hasBlock(gid)
      tree.localTipId == gid
      tree.blockHeight(gid) == Opt.some(0'u64)
      tree.fetchHeader(gid).get == genesis.header
      tree.latestImmutableBlockId == gid

  test "addBlockToTree extends chain and moves tip":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = mkChildValidBlock(genesis.header, gid, 1'u64)
      id1 = blockId(b1.header)
    check:
      tree.addBlockToTree(b1)
      tree.hasBlock(id1)
      tree.blockHeight(id1) == Opt.some(1'u64)
      tree.localTipId == id1
      tree.isAncestor(gid, id1)
      not tree.isAncestor(id1, gid)
      tree.isAncestor(gid, gid)

  test "addBlockToTree rejects duplicate id":
    let
      genesis = testGenesisBlock()
      tree = newLocalTree(genesis, 1'u64)
    check not tree.addBlockToTree(genesis)

  test "addBlockToTree rejects zero parent and unknown parent":
    let
      genesis = testGenesisBlock()
      tree = newLocalTree(genesis, 1'u64)
    var fakeParent: BlockId
    for i in 0 ..< fakeParent.len:
      fakeParent[i] = byte(i)
    let orphan = mkChildValidBlock(genesis.header, fakeParent, 1'u64)
    check not tree.addBlockToTree(orphan)
    let bad = mkChildValidBlock(genesis.header, default(BlockId), 99'u64)
    check not tree.addBlockToTree(bad)

  test "blockHeight returns none for unknown id":
    let tree = newLocalTree(testGenesisBlock(), 1'u64)
    var unknown: BlockId
    unknown[0] = 1'u8
    check tree.blockHeight(unknown).isNone

  test "latestImmutableBlockId walks back on tip branch":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = mkChildValidBlock(genesis.header, gid, 1'u64)
      id1 = blockId(b1.header)
      b2 = mkChildValidBlock(b1.header, id1, 2'u64)
    check tree.addBlockToTree(b1)
    tree.tryUpdateLib()
    check:
      tree.latestImmutableBlockId == gid
      tree.addBlockToTree(b2)
    tree.tryUpdateLib()
    check tree.latestImmutableBlockId == id1

suite "chain/local_tree (lcaBlockIdAndHeight)":
  test "lcaBlockIdAndHeight of genesis with itself is genesis":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, gid, gid).get()
    check:
      lcaId == gid
      lcaHeight == 0'u64

  test "lcaBlockIdAndHeight on a linear chain (depth and symmetry)":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = mkChildValidBlock(genesis.header, gid, 1'u64)
      id1 = blockId(b1.header)
      b2 = mkChildValidBlock(b1.header, id1, 2'u64)
      id2 = blockId(b2.header)
    check:
      tree.addBlockToTree(b1)
      tree.addBlockToTree(b2)
    block:
      let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, gid, id2).get()
      check:
        lcaId == gid
        lcaHeight == 0'u64
    block:
      let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, id1, id2).get()
      check:
        lcaId == id1
        lcaHeight == 1'u64
    block:
      let
        (a, _) = lcaBlockIdAndHeight(tree, id2, id1).get()
        (b, _) = lcaBlockIdAndHeight(tree, id1, id2).get()
      check a == b

  test "lcaBlockIdAndHeight across two children of genesis is genesis":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      left1 = mkChildValidBlock(genesis.header, gid, 1'u64)
      left1Id = blockId(left1.header)
      left2 = mkChildValidBlock(left1.header, left1Id, 2'u64)
      left2Id = blockId(left2.header)
      right = mkChildValidBlock(genesis.header, gid, 3'u64)
      rightId = blockId(right.header)
    check:
      tree.addBlockToTree(left1)
      tree.addBlockToTree(left2)
      tree.addBlockToTree(right)
    let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, left2Id, rightId).get()
    check:
      lcaId == gid
      lcaHeight == 0'u64

  test "lcaBlockIdAndHeight returns none if either id is unknown":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
    var unknown: BlockId
    unknown[0] = 7'u8
    check:
      lcaBlockIdAndHeight(tree, gid, unknown).isNone
      lcaBlockIdAndHeight(tree, unknown, gid).isNone
    
  test "addBlockToTree prunes side-branch nodes below finality height":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = mkChildValidBlock(genesis.header, gid, 1'u64)
      id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)
    let
      sideB = mkChildValidBlock(genesis.header, gid, 2'u64)
      idSide = blockId(sideB.header)
    check:
      tree.addBlockToTree(sideB)
      tree.blocksIdsAtHeight(1'u64).len == 2

    # Advance immutable block to b1 by adding b2 (height 2)
    let b2 = mkChildValidBlock(b1.header, id1, 3'u64)
    check tree.addBlockToTree(b2)
    tree.tryUpdateLib()

    # sideB is height 1, not ancestor of b2 -> pruned!
    check:
      not tree.hasBlock(idSide)
      tree.hasBlock(gid)
      tree.hasBlock(id1)
      # Single-element invariant for finalized height
      tree.blocksIdsAtHeight(1'u64).len == 1
      tree.blocksIdsAtHeight(1'u64)[0] == id1

  test "tryUpdateLib handles linear fast-path, cascades upward orphan pruning, and terminates early":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      # k = 2: immHeight = tip.height - 2
      tree = newLocalTree(genesis, securityParam = 2'u64)

      # 1. Build canonical chain up to height 3, verifying fast-path on linear chain
      b1 = mkChildValidBlock(genesis.header, gid, 1'u64)
      id1 = blockId(b1.header)
      b2 = mkChildValidBlock(b1.header, id1, 2'u64)
      id2 = blockId(b2.header)
      b3 = mkChildValidBlock(b2.header, id2, 3'u64)
      id3 = blockId(b3.header)

    check:
      tree.addBlockToTree(b1)
      tree.tryUpdateLib().len == 0 # Fast-path: no pruned blocks on linear chain
      tree.addBlockToTree(b2)
      tree.tryUpdateLib().len == 0 # Fast-path: no pruned blocks on linear chain
      tree.addBlockToTree(b3)
      tree.tryUpdateLib().len == 0 # Fast-path: no pruned blocks on linear chain

    # 2. Build competing fork branching off b1 (height 1):
    #    f2 at height 2, f3 at height 3
    let
      f2 = mkChildValidBlock(b1.header, id1, 10'u64)
      idF2 = blockId(f2.header)
      f3 = mkChildValidBlock(f2.header, idF2, 11'u64)
      idF3 = blockId(f3.header)

    check:
      tree.addBlockToTree(f2)
      tree.addBlockToTree(f3)
      # Before LIB update: all blocks are in the tree
      tree.hasBlock(idF2)
      tree.hasBlock(idF3)
      tree.blocksIdsAtHeight(3'u64).len == 2

    # 3. Add canonical b4, b5 (tip is now height 5)
    let
      b4 = mkChildValidBlock(b3.header, id3, 4'u64)
      id4 = blockId(b4.header)
      b5 = mkChildValidBlock(b4.header, id4, 5'u64)
      id5 = blockId(b5.header)
    check:
      tree.addBlockToTree(b4)
      tree.addBlockToTree(b5)

    # 4. Trigger LIB update:
    #    immHeight = 5 - 2 = 3 (new LIB is b3 at height 3).
    #    - Pass 1 prunes f2 at height 2.
    #    - Pass 2 prunes f3 at height 3 (missing parent f2).
    #    - Pass 2 checks height 4 (only canonical b4 exists, ids.len == 1) and breaks early!
    let pruned = tree.tryUpdateLib()
    check:
      tree.latestImmutableBlockId == id3
      idF2 in pruned
      idF3 in pruned
      # Neither f2 nor the floating island f3 should remain in the tree
      not tree.hasBlock(idF2)
      not tree.hasBlock(idF3)

    # Canonical blocks at all heights are intact
    for id in [gid, id1, id2, id3, id4, id5]:
      check tree.hasBlock(id)
    check tree.blocksIdsAtHeight(3'u64) == @[id3]

{.pop.}
