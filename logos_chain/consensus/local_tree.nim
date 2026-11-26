# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  std/[sets, tables],
  results,
  intops,
  ../core/types

type
  BlockNode = ref object
    id: BlockId
    parent: BlockNode
    slot: SlotNumber
    height: BlockNumber

  LocalTree* = ref object
    genesisId: BlockId
    blocksById: Table[BlockId, BlockNode]
    unfinalizedIdsByHeight: Table[BlockNumber, seq[BlockId]]
    tips: HashSet[BlockId]

func genesisId*(localTree: LocalTree): BlockId =
  localTree.genesisId

func tips*(localTree: LocalTree): lent HashSet[BlockId] =
  localTree.tips

func ancestorAtHeight*(localTree: LocalTree, id: BlockId, targetHeight: BlockNumber): Opt[BlockInfo] =
  localTree.blocksById.withValue(id, node):
    var n = node[]
    while n != nil:
      if n.height == targetHeight:
        return Opt.some(BlockInfo(id: n.id, slot: n.slot, height: n.height))
      if n.height < targetHeight:
        return Opt.none(BlockInfo)
      n = n.parent
  Opt.none(BlockInfo)

func init*(T: type LocalTree, genesisHeader: Header): LocalTree =
  let
    gid = blockId(genesisHeader)
    gn = BlockNode(id: gid, parent: nil, slot: genesisHeader.slot, height: 0'u64)
  LocalTree(
    genesisId: gid,
    blocksById: [(gid, gn)].toTable,
    tips: [gid].toHashSet,
  )

func blockHeight*(localTree: LocalTree, blockId: BlockId): Opt[BlockNumber] =
  localTree.blocksById.withValue(blockId, node):
    return Opt.some(node.height)
  Opt.none(BlockNumber)

func blockInfo*(localTree: LocalTree, blockId: BlockId): Opt[BlockInfo] =
  localTree.blocksById.withValue(blockId, node):
    return Opt.some(BlockInfo(id: node.id, slot: node.slot, height: node.height))
  Opt.none(BlockInfo)

# TODO: Canonical nodes strictly below LIB currently stay in `blocksById` forever because
# `ibd_server` walks ancestry back to peer `knownBlocks` and `checkViability` relies on
# `hasBlock` returning `AlreadyApplied` before the `slot <= LIB.slot` `UnviableFork` check.
# Once persistent header/block storage lands, sever `fromNode.parent = nil` and evict
# canonical `< LIB` nodes so `LocalTree` only holds the volatile tree rooted at LIB (~O(k)).
proc pruneForks*(localTree: LocalTree, newImmId: BlockId,
    oldImmHeight: BlockNumber): seq[BlockId] =
  var pruned: seq[BlockId]
  let fromNode = localTree.blocksById.getOrDefault(newImmId, nil)
  if fromNode == nil:
    return pruned

  # Pass 1: downward sweep — keep only canonical ancestors strictly above old LIB
  var curr = fromNode
  while curr != nil and curr.height > oldImmHeight:
    var ids: seq[BlockId]
    if localTree.unfinalizedIdsByHeight.pop(curr.height, ids):
      for id in ids:
        if id != curr.id:
          localTree.blocksById.del(id)
          localTree.tips.excl(id)
          pruned.add(id)
    curr = curr.parent

  # Fast path: if no forks were pruned below LIB, no orphans can exist above it
  if pruned.len == 0:
    return pruned

  # Pass 2: upward cascade — remove orphans whose parent was pruned.
  # Heights are strictly contiguous: every block at height h+1 has its parent at h.
  # If at any level h no block was pruned, no block at h+1 can be an orphan, so we stop.
  var h = fromNode.height + 1
  while true:
    var anyPrunedAtLevel = false
    localTree.unfinalizedIdsByHeight.withValue(h, ids):
      var kept: seq[BlockId]
      for id in ids[]:
        localTree.blocksById.withValue(id, node):
          if localTree.blocksById.hasKey(node.parent.id):
            kept.add(id)
          else:
            localTree.blocksById.del(id)
            localTree.tips.excl(id)
            pruned.add(id)
            anyPrunedAtLevel = true

      if anyPrunedAtLevel:
        ids[] = kept
        if ids[].len == 0:
          localTree.unfinalizedIdsByHeight.del(h)

    if not anyPrunedAtLevel:
      break # Cascade stopped: all parents at previous height were valid (or level h had no blocks)
    inc h

  pruned

func slotOf*(localTree: LocalTree, blockId: BlockId): Opt[SlotNumber] =
  localTree.blocksById.withValue(blockId, node):
    return Opt.some(node.slot)
  Opt.none(SlotNumber)

func parentOf*(localTree: LocalTree, blockId: BlockId): Opt[BlockId] =
  localTree.blocksById.withValue(blockId, node):
    if node.parent != nil:
      return Opt.some(node.parent.id)
  Opt.none(BlockId)

func hasBlock*(localTree: LocalTree, blockId: BlockId): bool =
  localTree.blocksById.hasKey(blockId)

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
    if node.slot <= lcaSlot:
      return 0'u64
    if node.slot <= maxSlot:
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

proc addHeaderToTree*(localTree: LocalTree, header: Header, id: BlockId): bool =
  ## Inserts a validated header (`id == blockId(header)`); only duplicate ids
  ## and unknown parents are guarded here.
  if localTree.blocksById.hasKey(id):
    return false
  localTree.blocksById.withValue(header.parentBlock, parent):
    let node = BlockNode(id: id, parent: parent[], slot: header.slot, height: parent.height + 1'u64)
    localTree.blocksById[id] = node
    localTree.unfinalizedIdsByHeight.mgetOrPut(node.height).add(id)
    localTree.tips.excl(header.parentBlock)
    localTree.tips.incl(id)
    return true
  false

{.pop.}
