# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  results,
  ../testutil,
  ../../logos_chain/core/[types, local_tree],
  ../../logos_chain/chain/genesis

suite "core/local_tree":
  test "newLocalTree stores genesis as tip at height 0":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
    check tree.hasBlock(gid)
    check tree.localTipId == gid
    check tree.blockHeight(gid) == Opt.some(0'u64)
    check tree.fetchHeader(gid).get == genesis.header
    check tree.latestImmutableBlockId == gid

  test "addBlockToTree extends chain and moves tip":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = childBlock(genesis.header, gid, 1'u64, [sm])
      id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)
    check tree.hasBlock(id1)
    check tree.blockHeight(id1) == Opt.some(1'u64)
    check tree.localTipId == id1
    check tree.isAncestor(gid, id1)
    check not tree.isAncestor(id1, gid)
    check tree.isAncestor(gid, gid)

  test "addBlockToTree rejects duplicate id":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      tree = newLocalTree(genesis, 1'u64)
    check not tree.addBlockToTree(genesis)

  test "addBlockToTree rejects zero parent and unknown parent":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      tree = newLocalTree(genesis, 1'u64)
    var fakeParent: BlockId
    for i in 0 ..< fakeParent.len:
      fakeParent[i] = byte(i)
    let orphan = childBlock(genesis.header, fakeParent, 1'u64, [sm])
    check not tree.addBlockToTree(orphan)
    let
      zeroParentHdr = initHeader(
        GenesisBedrockVersion,
        default(BlockId),
        99'u64,
        [sm],
        genesis.header.proofOfLeadership,
      )
      bad = initBlock(zeroParentHdr, txs = [sm])
    check not tree.addBlockToTree(bad)

  test "blockHeight returns none for unknown id":
    let tree = newLocalTree(createGenesisBlock(minimalSignedTx()), 1'u64)
    var unknown: BlockId
    unknown[0] = 1'u8
    check tree.blockHeight(unknown).isNone

  test "latestImmutableBlockId walks back on tip branch":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = childBlock(genesis.header, gid, 1'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, 2'u64, [sm])
    check tree.addBlockToTree(b1)
    tree.tryUpdateLib()
    check tree.latestImmutableBlockId == gid
    check tree.addBlockToTree(b2)
    tree.tryUpdateLib()
    check tree.latestImmutableBlockId == id1

  test "canExtend accepts child extending past immutable tip":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = childBlock(genesis.header, gid, 1'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, 2'u64, [sm])
    check tree.addBlockToTree(b1)
    tree.tryUpdateLib()
    check tree.addBlockToTree(b2)
    tree.tryUpdateLib()
    let b3 = childBlock(b2.header, blockId(b2.header), 3'u64, [sm])
    check tree.canExtend(b3.header)
    # A sibling forking at or before the immutable height is refused by canExtend.
    let replay = childBlock(genesis.header, gid, 4'u64, [sm])
    check not tree.canExtend(replay.header)

  test "canExtend mirrors the tree-dependent valid_header constraints":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = childBlock(genesis.header, gid, 5'u64, [sm])
      id1 = blockId(b1.header)
    check tree.canExtend(b1.header)
    check tree.addBlockToTree(b1)
    tree.tryUpdateLib()
    var unknown: BlockId
    unknown[0] = 9'u8
    check not tree.canExtend(childBlock(b1.header, unknown, 6'u64, [sm]).header)
    check not tree.canExtend(childBlock(b1.header, id1, 4'u64, [sm]).header)
    check not tree.canExtend(childBlock(b1.header, id1, 5'u64, [sm]).header)
    let b2 = childBlock(b1.header, id1, 6'u64, [sm])
    check tree.addBlockToTree(b2)
    tree.tryUpdateLib()
    check not tree.canExtend(childBlock(genesis.header, gid, 7'u64, [sm]).header)
    check tree.canExtend(childBlock(b2.header, blockId(b2.header), 7'u64, [sm]).header)

suite "core/local_tree (lcaBlockIdAndHeight)":
  test "lcaBlockIdAndHeight of genesis with itself is genesis":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
    let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, gid, gid).get()
    check lcaId == gid
    check lcaHeight == 0'u64

  test "lcaBlockIdAndHeight on a linear chain (depth and symmetry)":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = childBlock(genesis.header, gid, 1'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, 2'u64, [sm])
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
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      left1 = childBlock(genesis.header, gid, 1'u64, [sm])
      left1Id = blockId(left1.header)
      left2 = childBlock(left1.header, left1Id, 2'u64, [sm])
      left2Id = blockId(left2.header)
      right = childBlock(genesis.header, gid, 3'u64, [sm])
      rightId = blockId(right.header)
    check tree.addBlockToTree(left1)
    check tree.addBlockToTree(left2)
    check tree.addBlockToTree(right)
    let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, left2Id, rightId).get()
    check lcaId == gid
    check lcaHeight == 0'u64

  test "lcaBlockIdAndHeight returns none if either id is unknown":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
    var unknown: BlockId
    unknown[0] = 7'u8
    check lcaBlockIdAndHeight(tree, gid, unknown).isNone
    check lcaBlockIdAndHeight(tree, unknown, gid).isNone
    
  test "addBlockToTree prunes side-branch nodes below finality height":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = childBlock(genesis.header, gid, 1'u64, [sm])
      id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)
    let
      sideB = childBlock(genesis.header, gid, 2'u64, [sm])
      idSide = blockId(sideB.header)
    check tree.addBlockToTree(sideB)

    check tree.blocksIdsAtHeight(1'u64).len == 2

    # Advance immutable block to b1 by adding b2 (height 2)
    let b2 = childBlock(b1.header, id1, 3'u64, [sm])
    check tree.addBlockToTree(b2)
    tree.tryUpdateLib()

    # sideB is height 1, not ancestor of b2 -> pruned!
    check not tree.hasBlock(idSide)
    check tree.hasBlock(gid)
    check tree.hasBlock(id1)

    # Single-element invariant for finalized height
    check tree.blocksIdsAtHeight(1'u64).len == 1
    check tree.blocksIdsAtHeight(1'u64)[0] == id1

  test "canExtend rejects candidate blocks that do not descend from latestImmutableId":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = childBlock(genesis.header, gid, 1'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, 2'u64, [sm])
    check tree.addBlockToTree(b1)
    check tree.addBlockToTree(b2)
    tree.tryUpdateLib()

    # Candidate block extending genesis (which is below b1) -> rejected by canExtend!
    let invalidChild = childBlock(genesis.header, gid, 3'u64, [sm])
    check not tree.canExtend(invalidChild.header)

  test "tryUpdateLib handles linear fast-path, cascades upward orphan pruning, and terminates early":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      # k = 2: immHeight = tip.height - 2
      tree = newLocalTree(genesis, securityParam = 2'u64)

      # 1. Build canonical chain up to height 3, verifying fast-path on linear chain
      b1 = childBlock(genesis.header, gid, 1'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, 2'u64, [sm])
      id2 = blockId(b2.header)
      b3 = childBlock(b2.header, id2, 3'u64, [sm])
      id3 = blockId(b3.header)

    check tree.addBlockToTree(b1)
    check tree.tryUpdateLib().len == 0 # Fast-path: no pruned blocks on linear chain
    check tree.addBlockToTree(b2)
    check tree.tryUpdateLib().len == 0 # Fast-path: no pruned blocks on linear chain
    check tree.addBlockToTree(b3)
    check tree.tryUpdateLib().len == 0 # Fast-path: no pruned blocks on linear chain

    # 2. Build competing fork branching off b1 (height 1):
    #    f2 at height 2, f3 at height 3
    let
      f2 = childBlock(b1.header, id1, 10'u64, [sm])
      idF2 = blockId(f2.header)
      f3 = childBlock(f2.header, idF2, 11'u64, [sm])
      idF3 = blockId(f3.header)

    check tree.addBlockToTree(f2)
    check tree.addBlockToTree(f3)

    # Before LIB update: all blocks are in the tree
    check tree.hasBlock(idF2)
    check tree.hasBlock(idF3)
    check tree.blocksIdsAtHeight(3'u64).len == 2

    # 3. Add canonical b4, b5 (tip is now height 5)
    let
      b4 = childBlock(b3.header, id3, 4'u64, [sm])
      id4 = blockId(b4.header)
      b5 = childBlock(b4.header, id4, 5'u64, [sm])
      id5 = blockId(b5.header)
    check tree.addBlockToTree(b4)
    check tree.addBlockToTree(b5)

    # 4. Trigger LIB update:
    #    immHeight = 5 - 2 = 3 (new LIB is b3 at height 3).
    #    - Pass 1 prunes f2 at height 2.
    #    - Pass 2 prunes f3 at height 3 (missing parent f2).
    #    - Pass 2 checks height 4 (only canonical b4 exists, ids.len == 1) and breaks early!
    let pruned = tree.tryUpdateLib()
    check tree.latestImmutableBlockId == id3
    check idF2 in pruned
    check idF3 in pruned

    # Neither f2 nor the floating island f3 should remain in the tree
    check not tree.hasBlock(idF2)
    check not tree.hasBlock(idF3)

    # Canonical blocks at all heights are intact
    for id in [gid, id1, id2, id3, id4, id5]:
      check tree.hasBlock(id)
    check tree.blocksIdsAtHeight(3'u64) == @[id3]

{.pop.}
