# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  std/tables,
  results,
  bincode,
  ./types
from ./mantle/primitives import SlotNumber

export types.Block, types.Header, types.BlockId

type
  Tip* = object
    tip*: BlockId
    slot*: SlotNumber
    height*: uint64

deriveBincode(Tip)

type
  BlockNode = ref object
    id: BlockId
    blk: Block
    parent: BlockNode
    height: uint64

  LocalTree* = ref object
    blocks: Table[BlockId, BlockNode]
    tipId: BlockId
    latestImmutableHeight*: uint64

func isStrictlyHigherTip(currentTip, candidate: BlockNode): bool =
  candidate.height > currentTip.height

func ancestorAtHeight(node: BlockNode, targetHeight: uint64): BlockNode =
  var n = node
  while n != nil:
    if n.height == targetHeight:
      return n
    if n.height < targetHeight:
      return nil
    n = n.parent
  nil

func newLocalTree*(genesisBlock: Block, latestImmutableHeight: uint64 = 0): LocalTree =
  let gid = blockId(genesisBlock.header)
  let gn = BlockNode(id: gid, blk: genesisBlock, parent: nil, height: 0'u64)
  LocalTree(
    blocks: [(gid, gn)].toTable,
    tipId: gid,
    latestImmutableHeight: latestImmutableHeight,
  )

func blockHeight*(localTree: LocalTree, blockId: BlockId): Opt[uint64] =
  let n = localTree.blocks.getOrDefault(blockId, nil)
  if n == nil:
    Opt.none(uint64)
  else:
    Opt.some(n.height)

func fetchParentHeader*(localTree: LocalTree, parentBlock: BlockId): Opt[Header] =
  let n = localTree.blocks.getOrDefault(parentBlock, nil)
  if n == nil:
    Opt.none(Header)
  else:
    Opt.some(n.blk.header)

func hasBlock*(localTree: LocalTree, blockId: BlockId): bool =
  localTree.blocks.hasKey(blockId)

func getBlock*(localTree: LocalTree, id: BlockId): Opt[Block] =
  let n = localTree.blocks.getOrDefault(id, nil)
  if n == nil:
    Opt.none(Block)
  else:
    Opt.some(n.blk)

func localTipId*(localTree: LocalTree): BlockId =
  localTree.tipId

func latestImmutableBlockId*(localTree: LocalTree): BlockId =
  let tip = localTree.blocks.getOrDefault(localTree.tipId, nil)
  if tip == nil:
    return default(BlockId)
  let h = localTree.latestImmutableHeight
  if tip.height < h:
    return tip.id
  let a = ancestorAtHeight(tip, h)
  if a == nil:
    default(BlockId)
  else:
    a.id

func isAncestor*(localTree: LocalTree, ancestor: BlockId, descendant: BlockId): bool =
  if ancestor == descendant:
    return localTree.hasBlock(ancestor)
  let start = localTree.blocks.getOrDefault(descendant, nil)
  if start == nil:
    return false
  var n = start.parent
  while n != nil:
    if n.id == ancestor:
      return true
    n = n.parent
  false

func isFutureDescendantOfImmutable*(localTree: LocalTree, header: Header): bool =
  ## `height(B) > height(B_imm)` and `is_ancestor(B_imm, B)` over the parent
  ## chain (B is not yet in the tree).
  let parentHeight = blockHeight(localTree, header.parentBlock).valueOr:
    return false
  let candidateHeight = parentHeight + 1'u64
  if candidateHeight <= localTree.latestImmutableHeight:
    return false
  let immId = latestImmutableBlockId(localTree)
  if immId == default(BlockId):
    return true
  var cur = header.parentBlock
  while cur != default(BlockId):
    if cur == immId:
      return true
    let parentHeader = fetchParentHeader(localTree, cur).valueOr:
      return false
    cur = parentHeader.parentBlock
  false

func lcaBlockIdAndHeight*(
    localTree: LocalTree, idA, idB: BlockId,
): Opt[(BlockId, uint64)] =
  var na = localTree.blocks.getOrDefault(idA, nil)
  var nb = localTree.blocks.getOrDefault(idB, nil)
  if na == nil or nb == nil:
    return Opt.none((BlockId, uint64))
  while na.height > nb.height:
    na = na.parent
    if na == nil:
      return Opt.none((BlockId, uint64))
  while nb.height > na.height:
    nb = nb.parent
    if nb == nil:
      return Opt.none((BlockId, uint64))
  while na.id != nb.id:
    na = na.parent
    nb = nb.parent
    if na == nil or nb == nil:
      return Opt.none((BlockId, uint64))
  Opt.some((na.id, na.height))

proc addBlockToTree*(localTree: LocalTree, blk: Block): bool =
  let id = blockId(blk.header)
  if localTree.blocks.hasKey(id):
    return false
  let parentId = blk.header.parentBlock
  if parentId == default(BlockId):
    return false
  let parent = localTree.blocks.getOrDefault(parentId, nil)
  if parent == nil:
    return false
  let node = BlockNode(id: id, blk: blk, parent: parent, height: parent.height + 1'u64)
  localTree.blocks[id] = node
  let curTip = localTree.blocks.getOrDefault(localTree.tipId, nil)
  if curTip != nil and isStrictlyHigherTip(curTip, node):
    localTree.tipId = id
  true

{.pop.}
