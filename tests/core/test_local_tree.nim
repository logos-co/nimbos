# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import unittest2
import results

import ../../logos_chain/core/types
import ../../logos_chain/chain/genesis
import ../../logos_chain/core/mantle/tx_types
import ../../logos_chain/core/local_tree

proc minimalSignedTx(): SignedMantleTx =
  SignedMantleTx(
    tx: MantleTx(
      ops: @[],
      executionGasPrice: 0'u64,
      permanentStorageGasPrice: 0'u64,
    ),
    opProofs: @[],
  )

proc childBlock(parentHdr: Header, parentId: BlockId, slot: SlotNumber, txs: openArray[SignedMantleTx]): Block =
  let h = initHeader(
    bedrockVersion = parentHdr.bedrockVersion,
    parentBlock = parentId,
    slot = slot,
    txs = txs,
    proofOfLeadership = parentHdr.proofOfLeadership,
  )
  initBlock(h, txs = txs)

suite "core/local_tree":
  test "newLocalTree stores genesis as tip at height 0":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    check tree.hasBlock(gid)
    check tree.localTipId == gid
    check tree.blockHeight(gid) == Opt.some(0'u64)
    check tree.fetchParentHeader(gid).get == genesis.header
    check tree.latestImmutableBlockId == gid

  test "addBlockToTree extends chain and moves tip":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    let b1 = childBlock(genesis.header, gid, 1'u64, [sm])
    let id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)
    check tree.hasBlock(id1)
    check tree.blockHeight(id1) == Opt.some(1'u64)
    check tree.localTipId == id1
    check tree.isAncestor(gid, id1)
    check not tree.isAncestor(id1, gid)
    check tree.isAncestor(gid, gid)

  test "addBlockToTree rejects duplicate id":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    check not tree.addBlockToTree(genesis)

  test "addBlockToTree rejects zero parent and unknown parent":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    var fakeParent: BlockId
    for i in 0 ..< fakeParent.len:
      fakeParent[i] = byte(i)
    let orphan = childBlock(genesis.header, fakeParent, 1'u64, [sm])
    check not tree.addBlockToTree(orphan)
    let zeroParentHdr = initHeader(
      GenesisBedrockVersion,
      default(BlockId),
      99'u64,
      [sm],
      genesis.header.proofOfLeadership,
    )
    let bad = initBlock(zeroParentHdr, txs = [sm])
    check not tree.addBlockToTree(bad)

  test "blockHeight returns none for unknown id":
    let tree = newLocalTree(createGenesisBlock(minimalSignedTx()))
    var unknown: BlockId
    unknown[0] = 1'u8
    check tree.blockHeight(unknown).isNone

  test "latestImmutableBlockId walks back on tip branch":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis, latestImmutableHeight = 0'u64)
    let b1 = childBlock(genesis.header, gid, 1'u64, [sm])
    let id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)
    check tree.latestImmutableBlockId == gid
    tree.latestImmutableHeight = 1'u64
    check tree.latestImmutableBlockId == id1

  test "isFutureDescendantOfImmutable accepts child extending past immutable tip":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis, latestImmutableHeight = 0'u64)
    let b1 = childBlock(genesis.header, gid, 1'u64, [sm])
    check tree.isFutureDescendantOfImmutable(b1.header)

  test "isFutureDescendantOfImmutable rejects block at or before immutable height":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis, latestImmutableHeight = 1'u64)
    let b1 = childBlock(genesis.header, gid, 1'u64, [sm])
    check tree.addBlockToTree(b1)
    let id1 = blockId(b1.header)
    let b2 = childBlock(b1.header, id1, 2'u64, [sm])
    check tree.isFutureDescendantOfImmutable(b2.header)
    let replay = childBlock(genesis.header, gid, 1'u64, [sm])
    check not tree.isFutureDescendantOfImmutable(replay.header)

suite "core/local_tree (lcaBlockId)":
  test "lcaBlockId of genesis with itself is genesis":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    check lcaBlockId(tree, gid, gid) == Opt.some(gid)

  test "lcaBlockId on a linear chain (depth and symmetry)":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    let b1 = childBlock(genesis.header, gid, 1'u64, [sm])
    let id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)
    let b2 = childBlock(b1.header, id1, 2'u64, [sm])
    let id2 = blockId(b2.header)
    check tree.addBlockToTree(b2)
    let b3 = childBlock(b2.header, id2, 3'u64, [sm])
    let id3 = blockId(b3.header)
    check tree.addBlockToTree(b3)
    check lcaBlockId(tree, gid, id3) == Opt.some(gid)
    check lcaBlockId(tree, id1, id3) == Opt.some(id1)
    check lcaBlockId(tree, id2, id3) == Opt.some(id2)
    check lcaBlockId(tree, id3, id3) == Opt.some(id3)
    check lcaBlockId(tree, id3, id1) == lcaBlockId(tree, id1, id3)

  test "lcaBlockId across two children of genesis is genesis":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    let left = childBlock(genesis.header, gid, 1'u64, [sm])
    let right = childBlock(genesis.header, gid, 2'u64, [sm])
    check tree.addBlockToTree(left)
    check tree.addBlockToTree(right)
    let leftId = blockId(left.header)
    let rightId = blockId(right.header)
    check leftId != rightId
    check lcaBlockId(tree, leftId, rightId) == Opt.some(gid)

  test "lcaBlockId with tip branch and sibling branch meets at genesis":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    let onTip = childBlock(genesis.header, gid, 1'u64, [sm])
    check tree.addBlockToTree(onTip)
    let onTipId = blockId(onTip.header)
    let tipChild = childBlock(onTip.header, onTipId, 2'u64, [sm])
    check tree.addBlockToTree(tipChild)
    let tipChildId = blockId(tipChild.header)
    let sibling = childBlock(genesis.header, gid, 3'u64, [sm])
    check tree.addBlockToTree(sibling)
    let siblingId = blockId(sibling.header)
    check lcaBlockId(tree, tipChildId, siblingId) == Opt.some(gid)

  test "lcaBlockId returns none if either id is unknown":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    var unknown: BlockId
    unknown[0] = 7'u8
    check lcaBlockId(tree, gid, unknown).isNone
    check lcaBlockId(tree, unknown, gid).isNone

{.pop.}
