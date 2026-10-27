# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

## Spec: [Cryptarchia Bootstrapping & Synchronization](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/cryptarchia-v1-bootstr-sync.md)

{.push raises: [], gcsafe.}

import
  std/[sequtils, tables],
  chronicles,
  chronos,
  minilru,
  results,
  stew/byteutils,
  libp2p/[peerid, crypto/rng],
  ./[syncer_types, sync_client]

logScope:
  topics = "orphan_sync"

const
  DefaultMaxConcurrentOrphanSync = 2
  DefaultMaxOrphanRetries = 2
  OrphanFailureCooldownDuration = 30.seconds
  DefaultFailureCacheSize = 256

type
  OrphanError* {.pure.} = enum
    BehindImmutable
    ParentKnown
    InFlight
    CoolingDown
    AtCapacity

func init*(
    T: type OrphanSync,
    maxConcurrent: int = DefaultMaxConcurrentOrphanSync,
    failureCacheCap: int = DefaultFailureCacheSize,
): T =
  T(
    maxConcurrent: max(maxConcurrent, 1),
    active: initTable[BlockId, Future[void]](),
    recentFailures: LruCache[BlockId, Moment].init(max(failureCacheCap, 1)),
  )

func activeDownloadCount*(s: OrphanSync): int =
  s.active.len

func isCoolingDown*(s: OrphanSync, parentId: BlockId, now: Moment): bool =
  let failureTime = s.recentFailures.peek(parentId).valueOr:
    return false
  now - failureTime < OrphanFailureCooldownDuration

func checkFetch*(
    s: OrphanSync,
    tree: LocalTree,
    parentId: BlockId,
    slot: SlotNumber,
    now: Moment,
): Result[void, OrphanError] =
  if tree != nil:
    if slot <= tree.latestImmutableSlot():
      return err(OrphanError.BehindImmutable)
    if tree.hasBlock(parentId):
      return err(OrphanError.ParentKnown)

  if parentId in s.active:
    return err(OrphanError.InFlight)

  if s.isCoolingDown(parentId, now):
    return err(OrphanError.CoolingDown)

  if s.activeDownloadCount >= s.maxConcurrent:
    return err(OrphanError.AtCapacity)

  ok()

proc pickPeer(syncer: Syncer, candidates: openArray[PeerId]): PeerId =
  if syncer.sw != nil and syncer.sw.rng != nil:
    syncer.sw.rng.pickOne(candidates).valueOr(candidates[0])
  else:
    candidates[0]

proc resolveOrphanParent(
    syncer: Syncer,
    orphanId: BlockId,
    parentId: BlockId,
) {.async: (raises: [CancelledError]).} =
  defer:
    syncer.orphans.active.del(parentId)

  let parentHex = toHex(parentId)
  let orphanHex = toHex(orphanId)

  if syncer.peerProvider == nil:
    warn "Orphan DBR: no peer provider configured, cooling down",
      orphanId = orphanHex, parentId = parentHex
    syncer.orphans.recentFailures.put(parentId, Moment.now())
    return

  var attempts = 0
  var triedPeers: seq[PeerId]

  while attempts < DefaultMaxOrphanRetries:
    inc attempts
    let candidateList = syncer.peerProvider().filterIt(it notin triedPeers)
    if candidateList.len == 0:
      debug "Orphan DBR: no untried candidate peers available",
        orphanId = orphanHex, parentId = parentHex, attempt = attempts
      break

    let peer = syncer.pickPeer(candidateList)
    triedPeers.add(peer)

    debug "Orphan DBR: requesting missing ancestor from peer",
      orphanId = orphanHex, parentId = parentHex,
      peer, attempt = attempts

    let success = try:
      await syncer.downloadBlocks(peer, targetBlock = Opt.some(parentId))
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      debug "Orphan DBR: download failed with error",
        orphanId = orphanHex, parentId = parentHex,
        peer, err = exc.msg
      false

    if success:
      debug "Orphan DBR: successfully resolved missing ancestor",
        orphanId = orphanHex, parentId = parentHex,
        peer, attempt = attempts
      syncer.orphans.recentFailures.del(parentId)
      return

    debug "Orphan DBR: peer failed to provide ancestor",
      orphanId = orphanHex, parentId = parentHex,
      peer, attempt = attempts

  warn "Orphan DBR: all retries failed for missing ancestor, cooling down",
    orphanId = orphanHex, parentId = parentHex,
    attempts = attempts
  syncer.orphans.recentFailures.put(parentId, Moment.now())

proc handleOrphan*(
    syncer: Syncer,
    orphanId: BlockId,
    parentId: BlockId,
    slot: SlotNumber,
) =
  let now = Moment.now()
  syncer.orphans.checkFetch(syncer.localTree, parentId, slot, now).isOkOr:
    trace "Orphan DBR ignored",
      reason = $error,
      orphanId = toHex(orphanId),
      parentId = toHex(parentId)
    return

  let fut = syncer.resolveOrphanParent(orphanId, parentId)
  if not fut.finished:
    syncer.orphans.active[parentId] = fut
    asyncSpawn fut

proc stopOrphanSync*(syncer: Syncer) {.async: (raises: []).} =
  var futs: seq[Future[void]]
  for fut in syncer.orphans.active.values:
    if fut != nil and not fut.finished:
      futs.add(fut)
  for fut in futs:
    await fut.cancelAndWait()
  syncer.orphans.active.clear()

{.pop.}
