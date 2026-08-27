# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Logos Chain P2P peer discovery and Kademlia routing.
## Specs:
## - https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/draft/p2p-network.md#peer-discovery
## - https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/p2p-network-bootstrapping.md
## - https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/anoncomms/raw/extended-kad-disco.md

{.push raises: [], gcsafe.}

import
  std/[sets, sequtils],
  chronos, chronicles, results,
  libp2p/[switch, peerinfo, multiaddress, peerid, crypto/rng],
  libp2p/protocols/kademlia,
  libp2p/peerstore,
  ./peer_pool,
  ./bootstrap_nodes

export bootstrap_nodes

const
  KadBootstrapHeartbeatPeriod* = 10.minutes
  KadDiscoveryLookupPeriod* = 60.seconds

when defined(local_testnet) or defined(unittest) or defined(test):
  const KadDiscoveryLoopPeriod* = 200.milliseconds
else:
  const KadDiscoveryLoopPeriod* = 5.seconds

type
  DiscoveredPeerAddr* = tuple[peerId: PeerId, addrs: seq[MultiAddress]]

func hasRoutingPeers*(kad: KadDHT): bool =
  not isNil(kad) and kad.rtable.buckets.anyIt(it.peers.len > 0)

proc kadDiscoveryLookupWalk*(
    kad: KadDHT, rng: Rng
) {.async: (raises: [CancelledError]).} =
  if isNil(kad) or isNil(rng) or not kad.hasRoutingPeers():
    return
  let targetKey = rng.generateBytes(32)
  debug "Kad discovery findNode lookup walk"
  discard await kad.findNode(targetKey)

proc collectKadDiscoveredPeers[T](
    kad: KadDHT,
    sw: Switch,
    peerPool: PeerPool[T, PeerId],
): seq[DiscoveredPeerAddr] =
  if isNil(kad) or isNil(sw) or isNil(peerPool):
    return @[]
  var
    seen: HashSet[PeerId]
    discovered: seq[DiscoveredPeerAddr]
  let selfId = sw.peerInfo.peerId
  for bucket in kad.rtable.buckets:
    let peers = bucket.peers
    for entry in peers:
      let peerId = entry.nodeId.toPeerId().valueOr:
        continue
      if peerId == selfId or peerPool.hasPeer(peerId) or seen.containsOrIncl(peerId):
        continue
      let addrs = sw.peerStore[AddressBook][peerId]
      if addrs.len > 0:
        discovered.add((peerId: peerId, addrs: addrs))
  discovered

proc enqueueKadDiscoveredPeers*[T](
    kad: KadDHT,
    sw: Switch,
    peerPool: PeerPool[T, PeerId],
    enqueueIfEligible: proc(
      peer: DiscoveredPeerAddr
    ): Future[bool].Raising([CancelledError])
      {.gcsafe, raises: [].},
): Future[(int, int)] {.async: (raises: [CancelledError]).} =
  let discoveredPeers = collectKadDiscoveredPeers(kad, sw, peerPool)
  var queued = 0
  for discovered in discoveredPeers:
    if await enqueueIfEligible(discovered):
      inc queued
  (discoveredPeers.len, queued)

type
  BootstrapDial = proc(
    b: PeerInfo
  ): Future[bool].Raising([CancelledError]) {.gcsafe, raises: [].}

proc kadBootstrap*(
    kad: KadDHT,
    bootstrapNodes: seq[PeerInfo],
    dialBootstrapPeer: BootstrapDial,
) {.async: (raises: [CancelledError]).} =
  if isNil(kad) or bootstrapNodes.len == 0:
    return

  debug "Starting Kad bootstrap", peers = bootstrapNodes.len

  kad.updatePeers(bootstrapNodes)

  var dialFuts = newSeqOfCap[Future[bool].Raising([CancelledError])](bootstrapNodes.len)
  for b in bootstrapNodes:
    debug "Dialing bootstrap peer", peerId = b.peerId, addrs = b.addrs
    dialFuts.add dialBootstrapPeer(b)

  try:
    await allFutures(dialFuts)
  except CancelledError as exc:
    for fut in dialFuts:
      if not isNil(fut) and not fut.finished():
        fut.cancelSoon()
    raise exc

  var connectedCount = 0
  for i, fut in dialFuts:
    let b = bootstrapNodes[i]
    let dialSuccess =
      if fut.completed() and not fut.failed():
        try:
          fut.read()
        except FuturePendingError, CancelledError:
          false
      else:
        false

    if dialSuccess:
      inc connectedCount
      debug "Connected to bootstrap peer", peerId = b.peerId
    else:
      warn "Bootstrap peer not connected after dial attempt",
        peerId = b.peerId, addrs = b.addrs

  if connectedCount > 0:
    discard await kad.findNode(kad.rtable.selfId)

  info "Bootstrap lookup complete", connected = connectedCount

{.pop.}
