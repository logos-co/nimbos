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
  intops,
  bincode,
  ../core/types
from ../core/crypto/types as crypto_types import isZero
from ../core/mantle/primitives import SlotNumber, BlockNumber
from ./block_validation import ValidBlock, encode, header

export Block, Header, BlockId, ValidBlock, encode, header

type
  BlockNode = ref object
    id: BlockId
    blk: ValidBlock
    parent: BlockNode
    height: BlockNumber

  LocalTree* = ref object
    blocksById: Table[BlockId, BlockNode]
    idsByHeight: Table[BlockNumber, seq[BlockId]]

func ancestorAtHeight*(localTree: LocalTree, id: BlockId, targetHeight: BlockNumber): Opt[BlockId] =
  localTree.blocksById.withValue(id, node):
    var n = node[]
    while n != nil:
      if n.height == targetHeight:
        return Opt.some(n.id)
      if n.height < targetHeight:
        return Opt.none(BlockId)
      n = n.parent
  Opt.none(BlockId)

func init*(T: type LocalTree, genesisBlock: ValidBlock): LocalTree =
  let
    gid = blockId(genesisBlock.header)
    gn = BlockNode(id: gid, blk: genesisBlock, parent: nil, height: 0'u64)
  LocalTree(
    blocksById: [(gid, gn)].toTable,
    idsByHeight: [(0'u64, @[gid])].toTable,
  )

func blockHeight*(localTree: LocalTree, blockId: BlockId): Opt[BlockNumber] =
  localTree.blocksById.withValue(blockId, node):
    return Opt.some(node.height)
  Opt.none(BlockNumber)

proc pruneForks*(localTree: LocalTree, newImmId: BlockId,
    oldImmHeight: BlockNumber, tipHeight: BlockNumber): seq[BlockId] =
  var pruned: seq[BlockId]
  let fromNode = localTree.blocksById.getOrDefault(newImmId, nil)
  if fromNode == nil:
    return pruned

  # Pass 1: downward sweep — keep only canonical ancestors between new and old LIB
  var curr = fromNode
  while curr != nil:
    let h = curr.height
    localTree.idsByHeight.withValue(h, ids):
      if ids[].len > 1:
        for id in ids[]:
          if id != curr.id:
            localTree.blocksById.del(id)
            pruned.add(id)
        ids[] = @[curr.id]

    if h == oldImmHeight:
      break
    curr = curr.parent

  # Fast path: if no forks were pruned below LIB, no orphans can exist above it
  if pruned.len == 0:
    return pruned

  # Pass 2: upward cascade — remove orphans whose parent was pruned
  var anyPrunedAtLevel = true
  for h in (fromNode.height + 1) .. tipHeight:
    if not anyPrunedAtLevel:
      break # Cascade stopped: all parents at previous height were valid

    anyPrunedAtLevel = false
    localTree.idsByHeight.withValue(h, ids):
      if ids[].len > 1:
        var kept: seq[BlockId]
        for id in ids[]:
          localTree.blocksById.withValue(id, node):
            if localTree.blocksById.hasKey(node.parent.id):
              kept.add(id)
            else:
              localTree.blocksById.del(id)
              pruned.add(id)
              anyPrunedAtLevel = true

        if anyPrunedAtLevel:
          ids[] = kept

  pruned

func fetchHeader*(localTree: LocalTree, blockId: BlockId): Opt[Header] =
  localTree.blocksById.withValue(blockId, node):
    return Opt.some(node.blk.header)
  Opt.none(Header)

func hasBlock*(localTree: LocalTree, blockId: BlockId): bool =
  localTree.blocksById.hasKey(blockId)

func getBlock*(localTree: LocalTree, id: BlockId): Opt[ValidBlock] =
  localTree.blocksById.withValue(id, node):
    return Opt.some(node.blk)
  Opt.none(ValidBlock)

func isAncestor*(localTree: LocalTree, ancestor: BlockId,
    descendant: BlockId): bool =
  if ancestor == descendant:
    return localTree.hasBlock(ancestor)
  localTree.blocksById.withValue(descendant, start):
    var n = start.parent
    while n != nil:
      if n.id == ancestor:
        return true
      n = n.parent
  false

func lcaBlockIdAndHeight*(
    localTree: LocalTree, idA, idB: BlockId,
): Opt[(BlockId, BlockNumber)] =
  var
    na = localTree.blocksById.getOrDefault(idA, nil)
    nb = localTree.blocksById.getOrDefault(idB, nil)
  if na == nil or nb == nil:
    return Opt.none((BlockId, BlockNumber))
  if na.id == nb.id:
    return Opt.some((na.id, na.height))
  while na.height > nb.height:
    na = na.parent
    if na == nil:
      return Opt.none((BlockId, BlockNumber))
  while nb.height > na.height:
    nb = nb.parent
    if nb == nil:
      return Opt.none((BlockId, BlockNumber))
  while na.id != nb.id:
    na = na.parent
    nb = nb.parent
    if na == nil or nb == nil:
      return Opt.none((BlockId, BlockNumber))
  Opt.some((na.id, na.height))

# TODO: Backwards pointer traversal in highestAncestorInSlotWindow, lcaBlockIdAndHeight,
# and ancestorAtHeight is currently O(N). To optimize without breaking spec compliance:
# 1. Add binary-skip pointers to BlockNode (e.g. Bitcoin-style pskip / skipHeight(height))
#    to enable O(log N) ancestor and LCA lookups. In highestAncestorInSlotWindow, take skip
#    pointers while skip.slot > maxSlot, then step to parent (valid because slots strictly
#    increase along any chain).
# 2. Alternatively or additionally, compute candidate density inductively from parent:
#    if child.slot > maxSlot: density(child, lca) = density(parent, lca);
#    else: density(child, lca) = child.height - lcaHeight (O(1) with cached parent).
func highestAncestorInSlotWindow(
    localTree: LocalTree,
    tipId: BlockId,
    lcaSlot: SlotNumber,
    maxSlot: SlotNumber,
): uint64 =
  ## Returns the height of the highest ancestor of `tipId` whose slot <= maxSlot and slot > lcaSlot.
  ## Returns 0 if no block on the ancestor path falls in (lcaSlot, maxSlot].
  var node = localTree.blocksById.getOrDefault(tipId, nil)
  while node != nil:
    let slot = node.blk.header.slot
    if slot <= lcaSlot:
      return 0'u64
    if slot <= maxSlot:
      return node.height
    node = node.parent
  0'u64

func countChainDensity*(
    localTree: LocalTree,
    tipId: BlockId,
    lcaSlot: SlotNumber,
    lcaHeight: uint64,
    densitySlotWindow: uint64,
): uint64 =
  ## Counts primary blocks on the chain segment starting from `tipId` down towards LCA
  ## whose slot falls in the half-open interval (lcaSlot, lcaSlot + densitySlotWindow].
  ## Uses the mathematical property that density equals the height delta between the
  ## highest block in the window and the LCA: height(B_upper) - lcaHeight.
  ## If tip.slot <= maxSlot, this evaluates in O(1) without backwards traversal.
  let
    maxSlot = saturatingAdd(lcaSlot, densitySlotWindow)
    upperHeight = localTree.highestAncestorInSlotWindow(tipId, lcaSlot, maxSlot)
  if upperHeight <= lcaHeight:
    0'u64
  else:
    upperHeight - lcaHeight

proc addBlockToTree*(localTree: LocalTree, blk: ValidBlock): bool =
  ## Inserts a header-validated block; only duplicate ids and unknown parents
  ## are guarded here.
  let id = blockId(blk.header)
  if localTree.blocksById.hasKey(id):
    return false
  localTree.blocksById.withValue(blk.header.parentBlock, parent):
    let node = BlockNode(id: id, blk: blk, parent: parent[], height: parent.height + 1'u64)
    localTree.blocksById[id] = node
    localTree.idsByHeight.mgetOrPut(node.height, @[]).add(id)
    return true
  false

when defined(unittest) or defined(test):
  func blocksIdsAtHeight*(localTree: LocalTree, height: BlockNumber): seq[BlockId] =
    ## Returns a sequence of block IDs admitted at the specified height.
    localTree.idsByHeight.withValue(height, ids):
      return ids[]
    @[]

{.pop.}
