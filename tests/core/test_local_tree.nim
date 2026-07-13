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
      tree = newLocalTree(genesis)
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
      tree = newLocalTree(genesis)
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
      tree = newLocalTree(genesis)
    check not tree.addBlockToTree(genesis)

  test "addBlockToTree rejects zero parent and unknown parent":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      tree = newLocalTree(genesis)
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
    let tree = newLocalTree(createGenesisBlock(minimalSignedTx()))
    var unknown: BlockId
    unknown[0] = 1'u8
    check tree.blockHeight(unknown).isNone

  test "latestImmutableBlockId walks back on tip branch":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, latestImmutableHeight = 0'u64)
      b1 = childBlock(genesis.header, gid, 1'u64, [sm])
      id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)
    check tree.latestImmutableBlockId == gid
    tree.latestImmutableHeight = 1'u64
    check tree.latestImmutableBlockId == id1

  test "isFutureDescendantOfImmutable accepts child extending past immutable tip":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, latestImmutableHeight = 0'u64)
      b1 = childBlock(genesis.header, gid, 1'u64, [sm])
    check tree.isFutureDescendantOfImmutable(b1.header)

  test "isFutureDescendantOfImmutable rejects block at or before immutable height":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
      b1 = childBlock(genesis.header, gid, 1'u64, [sm])
    check tree.addBlockToTree(b1)
    tree.latestImmutableHeight = 1'u64
    let
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, 2'u64, [sm])
    check tree.isFutureDescendantOfImmutable(b2.header)
    # A sibling forking at or before the immutable height is refused by the
    # membership predicate and by insertion itself.
    let replay = childBlock(genesis.header, gid, 3'u64, [sm])
    check not tree.isFutureDescendantOfImmutable(replay.header)
    check not tree.addBlockToTree(replay)

  test "addBlockToTree rejects a child slot below its parent":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
      b1 = childBlock(genesis.header, gid, 5'u64, [sm])
      id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)
    check not tree.addBlockToTree(childBlock(b1.header, id1, 4'u64, [sm]))
    # Equal slots pass the tree; the strict ordering is the ledger's rule.
    check tree.addBlockToTree(childBlock(b1.header, id1, 5'u64, [sm]))

suite "core/local_tree (lcaBlockIdAndHeight)":
  test "lcaBlockIdAndHeight of genesis with itself is genesis":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
    let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, gid, gid).get()
    check lcaId == gid
    check lcaHeight == 0'u64

  test "lcaBlockIdAndHeight on a linear chain (depth and symmetry)":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
      b1 = childBlock(genesis.header, gid, 1'u64, [sm])
      id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)
    let
      b2 = childBlock(b1.header, id1, 2'u64, [sm])
      id2 = blockId(b2.header)
    check tree.addBlockToTree(b2)
    let
      b3 = childBlock(b2.header, id2, 3'u64, [sm])
      id3 = blockId(b3.header)
    check tree.addBlockToTree(b3)
    block:
      let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, gid, id3).get()
      check lcaId == gid
      check lcaHeight == 0'u64
    block:
      let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, id1, id3).get()
      check lcaId == id1
      check lcaHeight == 1'u64
    block:
      let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, id2, id3).get()
      check lcaId == id2
      check lcaHeight == 2'u64
    block:
      let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, id3, id3).get()
      check lcaId == id3
      check lcaHeight == 3'u64
    block:
      let (a, _) = lcaBlockIdAndHeight(tree, id3, id1).get()
      let (b, _) = lcaBlockIdAndHeight(tree, id1, id3).get()
      check a == b

  test "lcaBlockIdAndHeight across two children of genesis is genesis":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
      left = childBlock(genesis.header, gid, 1'u64, [sm])
      right = childBlock(genesis.header, gid, 2'u64, [sm])
    check tree.addBlockToTree(left)
    check tree.addBlockToTree(right)
    let
      leftId = blockId(left.header)
      rightId = blockId(right.header)
    check leftId != rightId
    let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, leftId, rightId).get()
    check lcaId == gid
    check lcaHeight == 0'u64

  test "lcaBlockIdAndHeight with tip branch and sibling branch meets at genesis":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
      onTip = childBlock(genesis.header, gid, 1'u64, [sm])
    check tree.addBlockToTree(onTip)
    let
      onTipId = blockId(onTip.header)
      tipChild = childBlock(onTip.header, onTipId, 2'u64, [sm])
    check tree.addBlockToTree(tipChild)
    let
      tipChildId = blockId(tipChild.header)
      sibling = childBlock(genesis.header, gid, 3'u64, [sm])
    check tree.addBlockToTree(sibling)
    let siblingId = blockId(sibling.header)
    let (lcaId, lcaHeight) = lcaBlockIdAndHeight(tree, tipChildId, siblingId).get()
    check lcaId == gid
    check lcaHeight == 0'u64

  test "lcaBlockIdAndHeight returns none if either id is unknown":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
    var unknown: BlockId
    unknown[0] = 7'u8
    check lcaBlockIdAndHeight(tree, gid, unknown).isNone
    check lcaBlockIdAndHeight(tree, unknown, gid).isNone

{.pop.}
