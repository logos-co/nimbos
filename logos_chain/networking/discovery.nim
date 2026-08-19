# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Logos Chain P2P peer discovery and Kademlia routing.
## Specs:
## - https://github.com/logos-co/logos-lips/blob/master/docs/blockchain/draft/p2p-network.md#peer-discovery
## - https://github.com/logos-co/logos-lips/blob/master/docs/blockchain/raw/p2p-network-bootstrapping.md
## - https://github.com/logos-co/logos-lips/blob/master/docs/anoncomms/raw/extended-kad-disco.md

{.push raises: [], gcsafe.}

import
  std/sets,
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

func hasDiscoveredKadPeers*(kad: KadDHT): bool =
  if isNil(kad):
    return false
  for bucket in kad.rtable.buckets:
    if bucket.peers.len > 0:
      return true
  return false

proc kadDiscoveryLookupWalk*(
    kad: KadDHT, rng: Rng
) {.async: (raises: [CancelledError]).} =
  if isNil(kad) or isNil(rng) or not hasDiscoveredKadPeers(kad):
    return
  let targetKey = rng.generateBytes(32)
  debug "Kad discovery findNode lookup walk"
  discard await kad.findNode(targetKey)

proc collectKadDiscoveredPeers[T](
    kad: KadDHT,
    sw: Switch,
    peerPool: PeerPool[T, PeerId],
): seq[DiscoveredPeerAddr] =
  if isNil(kad):
    return @[]
  var seen = initHashSet[PeerId]()
  for bucket in kad.rtable.buckets:
    for entry in bucket.peers:
      let pidRes = entry.nodeId.toPeerId()
      if pidRes.isErr():
        continue
      let peerId = pidRes.get()
      if peerPool.hasPeer(peerId):
        continue
      let addrs = sw.peerStore[AddressBook][peerId]
      if addrs.len == 0 or peerId in seen:
        continue
      seen.incl(peerId)
      result.add((peerId: peerId, addrs: addrs))

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
  BootstrapDial* = proc(
    b: PeerInfo
  ): Future[bool].Raising([CancelledError]) {.gcsafe, raises: [].}

proc logosKadBootstrap*(
    kad: KadDHT,
    bootstrapNodes: seq[PeerInfo],
    dialBootstrapPeer: BootstrapDial,
) {.async: (raises: [CancelledError]).} =
  debug "Starting Logos Kad bootstrap", peers = bootstrapNodes.len

  kad.updatePeers(bootstrapNodes)

  var connectedCount = 0
  for b in bootstrapNodes:
    debug "Dialing bootstrap peer", peerId = b.peerId, addrs = b.addrs
    if await dialBootstrapPeer(b):
      inc connectedCount
      debug "Connected to bootstrap peer", peerId = b.peerId
    else:
      warn "Bootstrap peer not connected after dial attempt",
        peerId = b.peerId, addrs = b.addrs

  if connectedCount > 0:
    discard await kad.findNode(kad.rtable.selfId)

  info "Bootstrap lookup complete", connected = connectedCount

{.pop.}
