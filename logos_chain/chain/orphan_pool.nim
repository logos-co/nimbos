# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [Cryptarchia Bootstrapping & Synchronization](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/cryptarchia-v1-bootstr-sync.md#overview)

{.push raises: [], gcsafe.}

import
  std/[deques, tables],
  results,
  ../core/types,
  ../core/local_tree

type
  OrphanPool* = ref object
    byBlockId: Table[BlockId, ValidBlock]
    byParentId: Table[BlockId, seq[BlockId]]
    arrivalOrder: Deque[BlockId]

const
  MaxOrphans* = 128
  MaxOrphanSlotAge* = SlotNumber(2160)

func len*(pool: OrphanPool): int =
  ## Returns the number of orphan blocks currently in the pool.
  ## Time: O(1) | Space: O(1)
  pool.byBlockId.len

func hasOrphan*(pool: OrphanPool, id: BlockId): bool =
  ## Checks if a block ID exists in the orphan pool.
  ## Time: O(1) avg | Space: O(1)
  pool.byBlockId.hasKey(id)

func getOrphan*(pool: OrphanPool, id: BlockId): Opt[ValidBlock] =
  ## Retrieves an orphan block by its ID if present.
  ## Time: O(1) avg | Space: O(1)
  pool.byBlockId.withValue(id, blk):
    return Opt.some(blk[])
  Opt.none(ValidBlock)

proc removeOrphan*(pool: OrphanPool, id: BlockId): bool =
  ## Removes a specific orphan by ID and cleans up its parent index entry.
  ## Time: O(K) avg, where K is the number of siblings (K <= 2 in practice) | Space: O(1)
  pool.byBlockId.withValue(id, blk):
    let parentId = blk[].header.parentBlock
    pool.byBlockId.del(id)

    pool.byParentId.withValue(parentId, childList):
      let idx = childList[].find(id)
      if idx >= 0:
        childList[].del(idx)
      if childList[].len == 0:
        pool.byParentId.del(parentId)
    return true
  false

proc takeChildren*(pool: OrphanPool, parentId: BlockId): seq[ValidBlock] =
  ## Extracts and removes all direct child blocks waiting on `parentId`.
  ## Time: O(K) avg, where K is the number of direct children | Space: O(K)
  var children: seq[ValidBlock]
  pool.byParentId.withValue(parentId, list):
    children = newSeqOfCap[ValidBlock](list[].len)
    for cid in list[]:
      pool.byBlockId.withValue(cid, childBlk):
        children.add(move(childBlk[]))
        pool.byBlockId.del(cid)
    pool.byParentId.del(parentId)
  children

proc pruneDescendants*(pool: OrphanPool, rootId: BlockId) =
  ## Purges all descendant subtrees waiting on `rootId` via iterative BFS traversal.
  ## Time: O(M), where M is the number of descendant nodes | Space: O(M) for BFS queue
  var queue = @[rootId]
  var idx = 0
  while idx < queue.len:
    let parent = queue[idx]
    inc idx
    pool.byParentId.withValue(parent, list):
      for cid in list[]:
        pool.byBlockId.del(cid)
        queue.add(cid)
      pool.byParentId.del(parent)

proc pruneStale*(pool: OrphanPool, currentSlot: SlotNumber) =
  ## Evicts all orphans whose slot age exceeds `MaxOrphanSlotAge` (2160 slots).
  ## Time: O(N) where N is pool size | Space: O(S) where S <= N is the number of stale nodes
  if pool.byBlockId.len == 0 or currentSlot <= MaxOrphanSlotAge:
    return

  let minSlot = currentSlot - MaxOrphanSlotAge
  var staleIds: seq[BlockId]
  for id, blk in pool.byBlockId:
    if blk.header.slot < minSlot:
      staleIds.add(id)

  for id in staleIds:
    if pool.removeOrphan(id):
      pool.pruneDescendants(id)

proc pruneIncompatibleWithImmutable*(pool: OrphanPool, localTree: LocalTree) =
  ## Evicts orphans (and their descendant subtrees) that cannot possibly
  ## descend from the latest immutable block in localTree.
  ## Time: O(N * D) worst case where N is pool size and D is tree depth | Space: O(I) where I <= N
  if pool.byBlockId.len == 0:
    return

  var invalidIds: seq[BlockId]
  for id, blk in pool.byBlockId:
    if not localTree.canDescendFromImmutable(blk.header):
      invalidIds.add(id)

  for id in invalidIds:
    if pool.removeOrphan(id):
      pool.pruneDescendants(id)

proc addOrphan*(
    pool: OrphanPool,
    blk: sink ValidBlock,
    currentSlot: SlotNumber,
): bool =
  ## Adds a validated orphan block to the pool, rejecting stale orphans,
  ## proactively evicting stale orphans, and evicting the oldest orphan if capacity is reached.
  ## Time: O(1) amortized | Space: O(1)
  if currentSlot >= blk.header.slot and currentSlot - blk.header.slot > MaxOrphanSlotAge:
    return false

  let id = blockId(blk.header)
  if pool.byBlockId.hasKey(id):
    return false

  pool.pruneStale(currentSlot)

  if pool.byBlockId.len >= MaxOrphans:
    while pool.arrivalOrder.len > 0:
      let oldestId = pool.arrivalOrder.popFirst()
      if pool.removeOrphan(oldestId):
        break
  elif pool.arrivalOrder.len > MaxOrphans * 2:
    while pool.arrivalOrder.len > 0 and not pool.byBlockId.hasKey(pool.arrivalOrder.peekFirst()):
      discard pool.arrivalOrder.popFirst()

  let parentId = blk.header.parentBlock
  pool.byBlockId[id] = move(blk)
  pool.arrivalOrder.addLast(id)
  pool.byParentId.mgetOrPut(parentId, @[]).add(id)
  true

{.pop.}
