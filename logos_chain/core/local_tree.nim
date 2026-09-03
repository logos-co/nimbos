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
from ./crypto/types as crypto_types import isZero
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
  localTree.blocks.withValue(blockId, n):
    return Opt.some(n.height)
  Opt.none(uint64)

func fetchParentHeader*(localTree: LocalTree, parentBlock: BlockId): Opt[Header] =
  localTree.blocks.withValue(parentBlock, n):
    return Opt.some(n.blk.header)
  Opt.none(Header)

func hasBlock*(localTree: LocalTree, blockId: BlockId): bool =
  localTree.blocks.hasKey(blockId)

func getBlock*(localTree: LocalTree, id: BlockId): Opt[Block] =
  localTree.blocks.withValue(id, n):
    return Opt.some(n.blk)
  Opt.none(Block)

func localTipId*(localTree: LocalTree): BlockId =
  localTree.tipId

func latestImmutableBlockId*(localTree: LocalTree): BlockId =
  localTree.blocks.withValue(localTree.tipId, tip):
    let h = localTree.latestImmutableHeight
    if tip.height < h:
      return tip.id
    let a = ancestorAtHeight(tip[], h)
    if a != nil:
      return a.id
  DefaultBlockId

func isAncestor*(localTree: LocalTree, ancestor: BlockId, descendant: BlockId): bool =
  if ancestor == descendant:
    return localTree.hasBlock(ancestor)
  localTree.blocks.withValue(descendant, start):
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
  if immId.isZero:
    return true
  var cur = header.parentBlock
  while not cur.isZero:
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

# https://github.com/logos-co/logos-lips/blob/d064449307d28a76b3555dc7b5064d15ee19d7f5/docs/blockchain/raw/cryptarchia-v1-protocol.md#block-header-validation
func canExtend*(localTree: LocalTree, header: Header): bool =
  if header.parentBlock.isZero:
    return false
  localTree.blocks.withValue(header.parentBlock, parent):
    return header.slot > parent.blk.header.slot and
      isFutureDescendantOfImmutable(localTree, header)
  false

proc addBlockToTree*(localTree: LocalTree, blk: Block): bool =
  ## Inserts a block the caller already passed through `canExtend`; only
  ## duplicate ids and unknown parents are guarded here.
  let id = blockId(blk.header)
  if localTree.blocks.hasKey(id):
    return false
  localTree.blocks.withValue(blk.header.parentBlock, parent):
    let node = BlockNode(id: id, blk: blk, parent: parent[], height: parent[].height + 1'u64)
    localTree.blocks[id] = node
    localTree.blocks.withValue(localTree.tipId, curTip):
      if isStrictlyHigherTip(curTip[], node):
        localTree.tipId = id
    return true
  false

{.pop.}
