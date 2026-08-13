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
    check tree.fetchParentHeader(gid).get == genesis.header
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

{.pop.}
