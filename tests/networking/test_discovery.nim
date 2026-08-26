# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  chronos,
  chronos/unittest2/asynctests,
  ../testutil

import
  ../../logos_chain/conf,
  ../../logos_chain/networking/[
    network,
    discovery,
    protocols,
    peer_pool,
    bootstrap_nodes
  ],
  libp2p/[switch, peerid, peerinfo, peerstore, multiaddress],
  libp2p/protocols/kademlia

suite "Kad discovery — peerstore, rtable, peer pool":
  asyncTest "AddressBook extend merges multiaddrs without duplicates":
    let keysSw = getRandomNetKeys()
    let pid = getRandomPeerId()
    let ma1 = MultiAddress.init("/ip4/127.0.0.1/udp/4111/quic-v1").tryGet()
    let ma2 = MultiAddress.init("/ip4/127.0.0.1/udp/4222/quic-v1").tryGet()

    let sw = await startQuicTestSwitch(keysSw)
    try:
      sw.peerStore[AddressBook].extend(pid, @[ma1])
      sw.peerStore[AddressBook].extend(pid, @[ma1, ma2])
      let addrs = sw.peerStore[AddressBook][pid]
      check addrs.len == 2
    finally:
      await sw.stop()

  asyncTest "enqueueKadDiscoveredPeers: nil Kad returns (0, 0)":
    let pool = newPeerPool[network.Peer, PeerId]()
    let (disc, q) = await enqueueKadDiscoveredPeers(
      nil, nil, pool,
      proc(p: DiscoveredPeerAddr): Future[bool] {.async: (raises: [CancelledError]).} = true
    )
    check disc == 0
    check q == 0
    check not hasRoutingPeers(nil)

  asyncTest "enqueueKadDiscoveredPeers respects rtable, AddressBook, and peer pool":
    let node = await startTestNode("kad-discovery-rtable-test", maxPeers = 16)

    let kad = node.mountedProtocols.kad
    check not isNil(kad)
    check not hasRoutingPeers(kad)

    let remotePeerId = getRandomPeerId()
    let remoteAddr =
      MultiAddress.init("/ip4/127.0.0.1/udp/4333/quic-v1").tryGet()

    try:
      var enqueueCalls = 0
      proc enqueueAll(p: DiscoveredPeerAddr): Future[bool] {.
          async: (raises: [CancelledError]).} =
        inc enqueueCalls
        return true

      let (emptyDisc, emptyQ) = await enqueueKadDiscoveredPeers(
        kad, node.switch, node.peerPool, enqueueAll)
      check emptyDisc == 0
      check emptyQ == 0

      check kad.rtable.insert(remotePeerId)
      check hasRoutingPeers(kad)
      node.switch.peerStore[AddressBook].extend(remotePeerId, @[remoteAddr])

      let (disc1, q1) = await enqueueKadDiscoveredPeers(
        kad, node.switch, node.peerPool, enqueueAll)
      check disc1 == 1
      check q1 == 1
      check enqueueCalls == 1

      let remotePeer = node.getPeer(remotePeerId)
      remotePeer.setDirection(PeerType.Outgoing)
      check node.peerPool.addPeerNoWait(remotePeer, PeerType.Outgoing) ==
        PeerStatus.Success

      enqueueCalls = 0
      let (disc2, q2) = await enqueueKadDiscoveredPeers(
        kad, node.switch, node.peerPool, enqueueAll)
      check disc2 == 0
      check q2 == 0
      check enqueueCalls == 0
    finally:
      await node.stop()

  asyncTest "kadDiscoveryLookupWalk: no-op when nil or routing table is empty":
    # When kad is nil, no exception or hanging occurs
    await kadDiscoveryLookupWalk(nil, getTestRng())
    await kadDiscoveryLookupWalk(nil, nil)

  asyncTest "kadDiscoveryLookupWalk: executes lookup walk on populated rtable":
    let node = await startTestNode("kad-lookup-walk-test", maxPeers = 8)

    let kad = node.mountedProtocols.kad
    let remotePeerId = getRandomPeerId()
    check kad.rtable.insert(remotePeerId)

    try:
      # Should sample 32 random bytes and query findNode without error using switch RNG
      await kadDiscoveryLookupWalk(kad, node.switch.rng)
    finally:
      await node.stop()

  asyncTest "logosKadBootstrap: nil or empty bootstrap nodes is safe no-op":
    await logosKadBootstrap(nil, @[], nil)

  asyncTest "logosKadBootstrap: dials bootstrap nodes and runs lookup on success":
    let listener = await startTestNode("kad-boot-listener", maxPeers = 8)
    let dialer = await startTestNode("kad-boot-dialer", maxPeers = 8)

    let kad = dialer.mountedProtocols.kad
    let bInfo = PeerInfo(
      peerId: listener.switch.peerInfo.peerId,
      addrs: listener.switch.peerInfo.addrs
    )

    var dialed = false
    proc dialPeer(b: PeerInfo): Future[bool] {.async: (raises: [CancelledError]).} =
      dialed = true
      try:
        let conn = await dialer.switch.dial(
          b.peerId, b.addrs, logosKadCodec(LogosNetworkKind.Testnet))
        not isNil(conn)
      except CancelledError as exc:
        raise exc
      except CatchableError:
        false

    try:
      await logosKadBootstrap(kad, @[bInfo], dialPeer)
      check dialed
    finally:
      await dialer.stop()
      await listener.stop()

  asyncTest "logosKadBootstrap: handles failed bootstrap dial without error":
    let node = await startTestNode("kad-bootstrap-fail-test", maxPeers = 8)
    let kad = node.mountedProtocols.kad
    let bPid = getRandomPeerId()
    let bAddr = MultiAddress.init("/ip4/127.0.0.1/udp/4333/quic-v1").tryGet()
    let bInfo = PeerInfo(peerId: bPid, addrs: @[bAddr])

    proc mockDialFail(b: PeerInfo): Future[bool] {.async: (raises: [CancelledError]).} =
      false

    try:
      await logosKadBootstrap(kad, @[bInfo], mockDialFail)
    finally:
      await node.stop()

suite "Bootstrap multiaddress parsing":
  test "parseBootstrapAddress: valid /ip4/ and /dns4/ addresses":
    let pid = getRandomPeerId()
    let pidStr = $pid

    let ip4AddrStr = "/ip4/127.0.0.1/udp/9000/quic-v1/p2p/" & pidStr
    let (ip4Pid, ip4Addr) = parseBootstrapAddress(ip4AddrStr).tryGet()
    check ip4Pid == pid
    check $ip4Addr == "/ip4/127.0.0.1/udp/9000/quic-v1"

    let dnsAddrStr = "/dns4/boot.logos.co/udp/9000/quic-v1/p2p/" & pidStr
    let (dnsPid, dnsAddr) = parseBootstrapAddress(dnsAddrStr).tryGet()
    check dnsPid == pid
    check $dnsAddr == "/dns4/boot.logos.co/udp/9000/quic-v1"

  test "parseBootstrapAddress: rejects invalid or non-QUIC addresses":
    let pid = getRandomPeerId()
    let pidStr = $pid

    # Empty
    check parseBootstrapAddress("").isErr
    check parseBootstrapAddress("   ").isErr

    # Not starting with /
    check parseBootstrapAddress("127.0.0.1:9000").isErr

    # Missing /p2p/
    check parseBootstrapAddress("/ip4/127.0.0.1/udp/9000/quic-v1").isErr

    # TCP instead of UDP/QUIC
    check parseBootstrapAddress("/ip4/127.0.0.1/tcp/9000/p2p/" & pidStr).isErr

    # Missing quic-v1
    check parseBootstrapAddress("/ip4/127.0.0.1/udp/9000/p2p/" & pidStr).isErr

  test "loadBootstrapNodes: filters valid nodes from NetworkConfig":
    let pid1 = getRandomPeerId()
    let pid2 = getRandomPeerId()

    let conf = NetworkConfig(
      bootstrapNodes: @[
        "/ip4/127.0.0.1/udp/9001/quic-v1/p2p/" & $pid1,
        "# this is a comment",
        "invalid-addr",
        "/ip4/127.0.0.1/udp/9002/quic-v1/p2p/" & $pid2,
        "/ip4/127.0.0.1/tcp/9003/p2p/" & $pid1 # rejected because TCP
      ]
    )
    let parsedNodes = loadBootstrapNodes(conf)
    check parsedNodes.len == 2
    check parsedNodes[0][0] == pid1
    check parsedNodes[1][0] == pid2

  test "loadBootstrapNodes: handles missing file gracefully":
    let confMissing = NetworkConfig(
      bootstrapNodesFile: InputFile("non_existent_bootstrap_file_12345.txt")
    )
    let nodesMissing = loadBootstrapNodes(confMissing)
    check nodesMissing.len == 0

  test "loadBootstrapNodes: deduplicates duplicate bootstrap nodes by peerId":
    let pid = getRandomPeerId()

    let conf = NetworkConfig(
      bootstrapNodes: @[
        "/ip4/127.0.0.1/udp/9001/quic-v1/p2p/" & $pid,
        "/ip4/127.0.0.1/udp/9001/quic-v1/p2p/" & $pid,
        "/ip4/127.0.0.2/udp/9002/quic-v1/p2p/" & $pid
      ]
    )
    let parsedNodes = loadBootstrapNodes(conf)
    check parsedNodes.len == 1
    check parsedNodes[0][0] == pid

suite "Bootstrap link maintenance and disconnection":
  test "bootstrapLinkMaintenanceShouldDisconnect: predicate boundaries":
    # Below target -> do not disconnect
    check not bootstrapLinkMaintenanceShouldDisconnect(
      peerPoolLen = 1, wantedPeers = 4, bootstrapPeersInPool = 1)
    check not bootstrapLinkMaintenanceShouldDisconnect(
      peerPoolLen = 3, wantedPeers = 4, bootstrapPeersInPool = 1)

    # At or above target, but all peers in pool are bootstrap nodes -> do not disconnect
    check not bootstrapLinkMaintenanceShouldDisconnect(
      peerPoolLen = 4, wantedPeers = 4, bootstrapPeersInPool = 4)
    check not bootstrapLinkMaintenanceShouldDisconnect(
      peerPoolLen = 6, wantedPeers = 4, bootstrapPeersInPool = 6)

    # At target with at least 1 non-bootstrap peer -> disconnect
    check bootstrapLinkMaintenanceShouldDisconnect(
      peerPoolLen = 4, wantedPeers = 4, bootstrapPeersInPool = 1)
    check bootstrapLinkMaintenanceShouldDisconnect(
      peerPoolLen = 4, wantedPeers = 4, bootstrapPeersInPool = 3)

    # Above target with non-bootstrap peers -> disconnect
    check bootstrapLinkMaintenanceShouldDisconnect(
      peerPoolLen = 8, wantedPeers = 4, bootstrapPeersInPool = 2)

  asyncTest "runBootstrapLinkMaintenanceTick: disconnects bootstrap peer when pool target is met":
    let bootNode = await startTestNode("bootstrap-node", maxPeers = 8)
    let bootPid = bootNode.switch.peerInfo.peerId
    let bootAddrs = bootNode.switch.peerInfo.addrs
    let bootAddrStr = bootNode.fullAddress()

    let clientNode = await startTestNode("client-node", @[bootAddrStr], maxPeers = 2)
    await clientNode.start()

    try:
      # Connect client to bootstrap peer
      let connected = await connectViaConnQueue(
        clientNode,
        bootNode.peerAddr(),
        alwaysAllowPeer,
        3.seconds
      )
      check connected
      check clientNode.switch.isConnected(bootPid)

      let bootPeer = clientNode.getPeer(bootPid)
      check clientNode.peerPool.hasPeer(bootPid)
      check bootPeer.connectionState == ConnectionState.Connected

      # With only 1 peer in pool (which is bootstrap) and wantedPeers=2 -> tick does not disconnect
      await runBootstrapLinkMaintenanceTick(clientNode)
      check clientNode.switch.isConnected(bootPid)
      check bootPeer.connectionState == ConnectionState.Connected

      # Add a second regular (non-bootstrap) peer to meet wantedPeers target (2)
      let regPid = getRandomPeerId()
      let regPeer = clientNode.getPeer(regPid)
      regPeer.connectionState = ConnectionState.Connected
      check clientNode.peerPool.addPeerNoWait(regPeer, PeerType.Outgoing) == PeerStatus.Success

      # Now poolLen = 2 >= wantedPeers (2), and non-bootstrap peers = 1.
      # Maintenance tick should trigger graceful disconnect on the bootstrap peer!
      await runBootstrapLinkMaintenanceTick(clientNode)
      check bootPeer.connectionState in {ConnectionState.Disconnecting, ConnectionState.Disconnected}
    finally:
      await clientNode.stop()
      await bootNode.stop()

{.pop.}
