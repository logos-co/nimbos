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
  results,
  stew/byteutils,
  libp2p/[peerid, crypto/rng],
  ../chain/orphan_pool,
  ./[syncer_types, sync_client]

logScope:
  topics = "orphan_sync"

const
  MaxConcurrentOrphanSync = 2
  MaxOrphanRetries = 3
  BaseBackoff = 1.seconds
  WatchdogTimeout = 60.seconds

func backoffDelay(attempts: int): Duration =
  ## BaseBackoff * 2^(attempts - 1). Bounded by MaxOrphanRetries.
  BaseBackoff * (1 shl clamp(attempts - 1, 0, MaxOrphanRetries))

func isCoolingDown*(syncer: Syncer, parentId: BlockId, now: Moment): bool =
  syncer.orphans.retries.withValue(parentId, entry):
    return now - entry[].lastAttempt < backoffDelay(entry[].attempts)
  false

func nextBackoffDuration*(syncer: Syncer, now: Moment): Opt[Duration] =
  var minWait = Duration.high
  for id, entry in syncer.orphans.retries:
    if id in syncer.orphans.active or not syncer.orphanPool.isMissingParent(id):
      continue
    let
      elapsed = now - entry.lastAttempt
      delay = backoffDelay(entry.attempts)
      remaining = if elapsed < delay: delay - elapsed else: ZeroDuration
    if remaining < minWait:
      minWait = remaining
      if minWait == ZeroDuration:
        break
  if minWait < Duration.high: Opt.some(minWait) else: Opt.none(Duration)

proc recordFailure*(syncer: Syncer, parentId: BlockId, now: Moment) =
  ## Records a failed fetch attempt for `parentId`. On the MaxOrphanRetries-th
  ## failure, drops every orphan waiting on it.
  let entry = addr syncer.orphans.retries.mgetOrPut(parentId, OrphanFetch())
  inc entry[].attempts
  entry[].lastAttempt = now
  if entry[].attempts >= MaxOrphanRetries:
    syncer.orphanPool.pruneDescendants(parentId)
    syncer.orphans.retries.del(parentId)
    syncer.orphans.triedPeers.del(parentId)

proc pickPeer(syncer: Syncer, candidates: openArray[PeerId]): PeerId =
  if syncer.sw != nil and syncer.sw.rng != nil:
    syncer.sw.rng.pickOne(candidates).valueOr(candidates[0])
  else:
    candidates[0]

proc nextPeer*(syncer: Syncer, parentId: BlockId): Opt[PeerId] =
  ## Picks a random untried peer for `parentId`. Once every peer was tried,
  ## starts a new round instead of spending an attempt on nobody.
  let peers = if syncer.peerProvider == nil: @[] else: syncer.peerProvider()
  if peers.len == 0:
    return Opt.none(PeerId)

  let tried = addr syncer.orphans.triedPeers.mgetOrPut(parentId, @[])
  var candidates =
    if tried[].len > 0:
      peers.filterIt(it notin tried[])
    else:
      peers
  if candidates.len == 0:
    # All peers were tried: start a new round
    tried[].setLen(0)
    candidates = peers

  let peer = syncer.pickPeer(candidates)
  tried[].add(peer)
  Opt.some(peer)

proc fetchParent*(syncer: Syncer, parentId: BlockId) {.async: (raises: [CancelledError]).} =
  ## One download attempt for `parentId`. Resolution is read from the pool:
  ## applying the parent makes the processor take its children, which clears
  ## the missing entry.
  let
    pool = syncer.orphanPool
    peer = syncer.nextPeer(parentId).valueOr:
      debug "Orphan DBR: no peers", parentId = toHex(parentId)
      if pool.isMissingParent(parentId):
        syncer.recordFailure(parentId, Moment.now())
      return

  defer:
    syncer.orphans.active.del(parentId)
    syncer.processor.orphanEvent.fire()

  if syncer.sw != nil:
    debug "Orphan DBR: requesting missing ancestor",
      parentId = toHex(parentId), peer
    discard await syncer.downloadBlocks(peer, targetBlock = parentId)

  if pool.isMissingParent(parentId):
    debug "Orphan DBR: ancestor still missing", parentId = toHex(parentId)
    syncer.recordFailure(parentId, Moment.now())
  else:
    syncer.orphans.retries.del(parentId)
    syncer.orphans.triedPeers.del(parentId)

proc dropStaleSyncState(syncer: Syncer) =
  ## Parents resolved, pruned or evicted no longer need sync state.
  if syncer.orphans.triedPeers.len == 0 and syncer.orphans.retries.len == 0:
    return

  template dropFoundParent(table: untyped) =
    var stale: seq[BlockId]
    for id in table.keys:
      if not syncer.orphanPool.isMissingParent(id):
        stale.add(id)
    for id in stale:
      table.del(id)

  dropFoundParent(syncer.orphans.triedPeers)
  dropFoundParent(syncer.orphans.retries)

proc runOrphanSyncLoop(syncer: Syncer) {.async: (raises: [CancelledError]).} =
  let pool = syncer.orphanPool
  while true:
    # Clear first: anything firing from here on re-arms the next wait.
    syncer.processor.orphanEvent.clear()
    syncer.dropStaleSyncState()

    let now = Moment.now()
    var toFetch: seq[BlockId]
    for parentId in pool.missingParentIds:
      if syncer.orphans.active.len + toFetch.len >= MaxConcurrentOrphanSync:
        break
      if parentId notin syncer.orphans.active and not syncer.isCoolingDown(parentId, now):
        toFetch.add(parentId)

    for parentId in toFetch:
      let fut = syncer.fetchParent(parentId)
      if not fut.finished:
        syncer.orphans.active[parentId] = fut

    # Saturated: only a finished fetch (which fires the event) frees a slot.
    # Otherwise wake when the next backoff expires.
    let timeout =
      if syncer.orphans.active.len >= MaxConcurrentOrphanSync:
        WatchdogTimeout
      else:
        syncer.nextBackoffDuration(now).valueOr(WatchdogTimeout)
    discard await syncer.processor.orphanEvent.wait().withTimeout(timeout)

proc startOrphanSync*(syncer: Syncer) =
  doAssert syncer.orphanLoopFut == nil, "orphan sync already started"
  syncer.orphanLoopFut = syncer.runOrphanSyncLoop()

proc stopOrphanSync*(syncer: Syncer) {.async: (raises: []).} =
  if syncer.orphanLoopFut != nil:
    await syncer.orphanLoopFut.cancelAndWait()
    syncer.orphanLoopFut = nil

  await cancelAndWait(toSeq(syncer.orphans.active.values))

{.pop.}
