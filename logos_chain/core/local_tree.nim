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
    blocksById: Table[BlockId, BlockNode]
    idsByHeight: Table[uint64, seq[BlockId]]
    tipId: BlockId
    latestImmutableId: BlockId
    securityParam: uint64

func ancestorAtHeight(node: BlockNode, targetHeight: uint64): BlockNode =
  var n = node
  while n != nil:
    if n.height == targetHeight:
      return n
    if n.height < targetHeight:
      return nil
    n = n.parent
  nil

func newLocalTree*(genesisBlock: Block, securityParam: uint64): LocalTree =
  let gid = blockId(genesisBlock.header)
  let gn = BlockNode(id: gid, blk: genesisBlock, parent: nil, height: 0'u64)
  LocalTree(
    blocksById: [(gid, gn)].toTable,
    idsByHeight: [(0'u64, @[gid])].toTable,
    tipId: gid,
    latestImmutableId: gid,
    securityParam: securityParam,
  )

func blockHeight*(localTree: LocalTree, blockId: BlockId): Opt[uint64] =
  localTree.blocksById.withValue(blockId, node):
    return Opt.some(node[].height)
  Opt.none(uint64)

func latestImmutableHeight*(localTree: LocalTree): uint64 =
  localTree.blocksById.withValue(localTree.latestImmutableId, node):
    return node[].height
  0'u64

proc pruneForks(localTree: LocalTree, fromNode: BlockNode,
    untilHeight: uint64, tipHeight: uint64): seq[BlockId] =
  var pruned: seq[BlockId]
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

    if h == untilHeight:
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
            if localTree.blocksById.hasKey(node[].parent.id):
              kept.add(id)
            else:
              localTree.blocksById.del(id)
              pruned.add(id)
              anyPrunedAtLevel = true

        if anyPrunedAtLevel:
          ids[] = kept

  pruned

# https://github.com/logos-co/logos-lips/blob/0ba596cfbd65ea4e9fd16ae572a848fcb43a45d5/docs/blockchain/raw/cryptarchia-v1-protocol.md#L338-L382
proc tryUpdateLib*(localTree: LocalTree): seq[BlockId] {.discardable.} =
  localTree.blocksById.withValue(localTree.tipId, tip):
    if tip[].height >= localTree.securityParam:
      let immHeight = tip[].height - localTree.securityParam
      if immHeight > localTree.latestImmutableHeight():
        let newImmNode = ancestorAtHeight(tip[], immHeight)
        if newImmNode != nil:
          let oldImmHeight = localTree.latestImmutableHeight()
          localTree.latestImmutableId = newImmNode.id
          return localTree.pruneForks(newImmNode, oldImmHeight, tip[].height)
  @[]

func fetchHeader*(localTree: LocalTree, blockId: BlockId): Opt[Header] =
  localTree.blocksById.withValue(blockId, node):
    return Opt.some(node[].blk.header)
  Opt.none(Header)

func localTip*(localTree: LocalTree): Tip =
  localTree.blocksById.withValue(localTree.tipId, node):
    return Tip(
      tip: localTree.tipId,
      slot: node[].blk.header.slot,
      height: node[].height,
    )
  raiseAssert "LocalTree invariant violated: tipId not in blocksById"

func hasBlock*(localTree: LocalTree, blockId: BlockId): bool =
  localTree.blocksById.hasKey(blockId)

func getBlock*(localTree: LocalTree, id: BlockId): Opt[Block] =
  localTree.blocksById.withValue(id, node):
    return Opt.some(node[].blk)
  Opt.none(Block)

func blocksIdsAtHeight*(localTree: LocalTree, height: uint64): seq[BlockId] =
  ## Returns a sequence of block IDs admitted at the specified height.
  localTree.idsByHeight.getOrDefault(height, @[])

func localTipId*(localTree: LocalTree): BlockId =
  ## Returns the BlockId of the current active tip.
  localTree.tipId

func latestImmutableBlockId*(localTree: LocalTree): BlockId =
  ## Returns the BlockId of the current Latest Immutable Block.
  localTree.latestImmutableId

func isAncestor*(localTree: LocalTree, ancestor: BlockId,
    descendant: BlockId): bool =
  if ancestor == descendant:
    return localTree.hasBlock(ancestor)
  localTree.blocksById.withValue(descendant, start):
    var n = start[].parent
    while n != nil:
      if n.id == ancestor:
        return true
      n = n.parent
  false

func isFutureDescendantOfImmutable(localTree: LocalTree,
    header: Header): bool =
  ## Validates that an incoming block header descends from `latestImmutableId` and has candidate height > immutableHeight.
  let parentHeight = blockHeight(localTree, header.parentBlock).valueOr:
    return false
  let candidateHeight = parentHeight + 1'u64
  if candidateHeight <= localTree.latestImmutableHeight():
    return false
  let immId = localTree.latestImmutableId
  if immId.isZero:
    return true
  var cur = header.parentBlock
  while not cur.isZero:
    if cur == immId:
      return true
    let parentHeader = fetchHeader(localTree, cur).valueOr:
      return false
    cur = parentHeader.parentBlock
  false

func lcaBlockIdAndHeight*(
    localTree: LocalTree, idA, idB: BlockId,
): Opt[(BlockId, uint64)] =
  var na = localTree.blocksById.getOrDefault(idA, nil)
  var nb = localTree.blocksById.getOrDefault(idB, nil)
  if na == nil or nb == nil:
    return Opt.none((BlockId, uint64))
  if na.id == nb.id:
    return Opt.some((na.id, na.height))
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
  localTree.blocksById.withValue(header.parentBlock, parent):
    return header.slot > parent.blk.header.slot and
      isFutureDescendantOfImmutable(localTree, header)
  false

proc addBlockToTree*(localTree: LocalTree, blk: Block): bool =
  ## Inserts a block the caller already passed through `canExtend`; only
  ## duplicate ids and unknown parents are guarded here.
  let id = blockId(blk.header)
  if localTree.blocksById.hasKey(id):
    return false
  localTree.blocksById.withValue(blk.header.parentBlock, parent):
    let node = BlockNode(id: id, blk: blk, parent: parent[], height: parent[].height + 1'u64)
    localTree.blocksById[id] = node
    localTree.idsByHeight.mgetOrPut(node.height, @[]).add(id)
    localTree.blocksById.withValue(localTree.tipId, curTip):
      if node.height > curTip[].height:
        localTree.tipId = id
    return true
  false

{.pop.}
