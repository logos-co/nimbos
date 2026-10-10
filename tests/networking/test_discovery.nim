# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  chronos/unittest2/asynctests,
  ../testutil,
  ../../logos_chain/conf,
  ../../logos_chain/networking/network,
  libp2p/switch,
  libp2p/protocols/kademlia

suite "Kad discovery — peerstore, rtable, peer pool":
  asyncTest "AddressBook extend merges multiaddrs without duplicates":
    let
      keysSw = getRandomNetKeys()
      pid = getRandomPeerId()
      ma1 = MultiAddress.init("/ip4/127.0.0.1/udp/4111/quic-v1").tryGet()
      ma2 = MultiAddress.init("/ip4/127.0.0.1/udp/4222/quic-v1").tryGet()

      sw = await startQuicTestSwitch(keysSw)
    try:
      sw.peerStore[AddressBook].extend(pid, @[ma1])
      sw.peerStore[AddressBook].extend(pid, @[ma1, ma2])
      let addrs = sw.peerStore[AddressBook][pid]
      check addrs.len == 2
    finally:
      await sw.stop()

  asyncTest "enqueueKadDiscoveredPeers: nil Kad returns (0, 0)":
    let
      pool = newPeerPool[network.Peer, PeerId]()
      (disc, q) = await enqueueKadDiscoveredPeers(
        nil, nil, pool,
        proc(p: DiscoveredPeerAddr): Future[bool] {.async: (raises: [CancelledError]).} = true
        )
    check:
      disc == 0
      q == 0
      not hasRoutingPeers(nil)

  asyncTest "enqueueKadDiscoveredPeers respects rtable, AddressBook, and peer pool":
    let
      node = await startTestNode("kad-discovery-rtable-test", maxPeers = 16)

      kad = node.mountedProtocols.kad
    check:
      not isNil(kad)
      not hasRoutingPeers(kad)

    let
      remotePeerId = getRandomPeerId()
      remoteAddr = MultiAddress.init("/ip4/127.0.0.1/udp/4333/quic-v1").tryGet()

    try:
      var enqueueCalls = 0
      proc enqueueAll(p: DiscoveredPeerAddr): Future[bool] {.
          async: (raises: [CancelledError]).} =
        inc enqueueCalls
        return true

      let (emptyDisc, emptyQ) = await enqueueKadDiscoveredPeers(
        kad, node.switch, node.peerPool, enqueueAll)
      check:
        emptyDisc == 0
        emptyQ == 0
        kad.rtable.insert(remotePeerId)
        hasRoutingPeers(kad)
      node.switch.peerStore[AddressBook].extend(remotePeerId, @[remoteAddr])

      let (disc1, q1) = await enqueueKadDiscoveredPeers(
        kad, node.switch, node.peerPool, enqueueAll)
      check:
        disc1 == 1
        q1 == 1
        enqueueCalls == 1

      let remotePeer = node.getPeer(remotePeerId)
      remotePeer.setDirection(PeerType.Outgoing)
      check node.peerPool.addPeerNoWait(remotePeer, PeerType.Outgoing) ==
        PeerStatus.Success

      enqueueCalls = 0
      let (disc2, q2) = await enqueueKadDiscoveredPeers(
        kad, node.switch, node.peerPool, enqueueAll)
      check:
        disc2 == 0
        q2 == 0
        enqueueCalls == 0
    finally:
      await node.stop()

  asyncTest "kadDiscoveryLookupWalk: no-op when nil or routing table is empty":
    # When kad is nil, no exception or hanging occurs
    await kadDiscoveryLookupWalk(nil, getTestRng())
    await kadDiscoveryLookupWalk(nil, nil)

  asyncTest "kadDiscoveryLookupWalk: executes lookup walk on populated rtable":
    let
      node = await startTestNode("kad-lookup-walk-test", maxPeers = 8)

      kad = node.mountedProtocols.kad
      remotePeerId = getRandomPeerId()
    check kad.rtable.insert(remotePeerId)

    try:
      # Should sample 32 random bytes and query findNode without error using switch RNG
      await kadDiscoveryLookupWalk(kad, node.switch.rng)
    finally:
      await node.stop()

  asyncTest "kadBootstrap: nil or empty bootstrap nodes is safe no-op":
    await kadBootstrap(nil, @[], nil)

  asyncTest "kadBootstrap: dials bootstrap nodes and runs lookup on success":
    let
      listener = await startTestNode("kad-boot-listener", maxPeers = 8)
      dialer = await startTestNode("kad-boot-dialer", maxPeers = 8)

      kad = dialer.mountedProtocols.kad
      bInfo = PeerInfo(
        peerId: listener.switch.peerInfo.peerId,
        addrs: listener.switch.peerInfo.addrs
        )

    var dialed = false
    proc dialPeer(b: PeerInfo): Future[bool] {.async: (raises: [CancelledError]).} =
      dialed = true
      try:
        let conn = await dialer.switch.dial(
          b.peerId, b.addrs, kadCodec(LogosNetworkKind.Testnet))
        not isNil(conn)
      except CancelledError as exc:
        raise exc
      except CatchableError:
        false

    try:
      await kadBootstrap(kad, @[bInfo], dialPeer)
      check dialed
    finally:
      await dialer.stop()
      await listener.stop()

  asyncTest "kadBootstrap: handles failed bootstrap dial without error":
    let
      node = await startTestNode("kad-bootstrap-fail-test", maxPeers = 8)
      kad = node.mountedProtocols.kad
      bPid = getRandomPeerId()
      bAddr = MultiAddress.init("/ip4/127.0.0.1/udp/4333/quic-v1").tryGet()
      bInfo = PeerInfo(peerId: bPid, addrs: @[bAddr])

    proc mockDialFail(b: PeerInfo): Future[bool] {.async: (raises: [CancelledError]).} =
      false

    try:
      await kadBootstrap(kad, @[bInfo], mockDialFail)
    finally:
      await node.stop()

suite "Bootstrap multiaddress parsing":
  test "parseBootstrapAddress: valid /ip4/ and /dns4/ addresses":
    let
      pid = getRandomPeerId()
      pidStr = $pid

      ip4AddrStr = "/ip4/127.0.0.1/udp/9000/quic-v1/p2p/" & pidStr
      (ip4Pid, ip4Addr) = parseBootstrapAddress(ip4AddrStr).tryGet()
    check:
      ip4Pid == pid
      $ip4Addr == "/ip4/127.0.0.1/udp/9000/quic-v1"

    let
      dnsAddrStr = "/dns4/boot.logos.co/udp/9000/quic-v1/p2p/" & pidStr
      (dnsPid, dnsAddr) = parseBootstrapAddress(dnsAddrStr).tryGet()
    check:
      dnsPid == pid
      $dnsAddr == "/dns4/boot.logos.co/udp/9000/quic-v1"

  test "parseBootstrapAddress: rejects invalid or non-QUIC addresses":
    let
      pid = getRandomPeerId()
      pidStr = $pid

    # Empty
    check:
      parseBootstrapAddress("").isErr
      parseBootstrapAddress("   ").isErr
      # Not starting with /
      parseBootstrapAddress("127.0.0.1:9000").isErr
      # Missing /p2p/
      parseBootstrapAddress("/ip4/127.0.0.1/udp/9000/quic-v1").isErr
      # TCP instead of UDP/QUIC
      parseBootstrapAddress("/ip4/127.0.0.1/tcp/9000/p2p/" & pidStr).isErr
      # Missing quic-v1
      parseBootstrapAddress("/ip4/127.0.0.1/udp/9000/p2p/" & pidStr).isErr

  test "loadBootstrapNodes: filters valid nodes from NetworkConfig":
    let
      pid1 = getRandomPeerId()
      pid2 = getRandomPeerId()

      conf = NetworkConfig(
        bootstrapNodes: @[
        "/ip4/127.0.0.1/udp/9001/quic-v1/p2p/" & $pid1,
        "# this is a comment",
        "invalid-addr",
        "/ip4/127.0.0.1/udp/9002/quic-v1/p2p/" & $pid2,
        "/ip4/127.0.0.1/tcp/9003/p2p/" & $pid1 # rejected because TCP
        ]
        )
      parsedNodes = loadBootstrapNodes(conf)
    check:
      parsedNodes.len == 2
      parsedNodes[0][0] == pid1
      parsedNodes[1][0] == pid2

  test "loadBootstrapNodes: handles missing file gracefully":
    let
      confMissing = NetworkConfig(
        bootstrapNodesFile: InputFile("non_existent_bootstrap_file_12345.txt")
        )
      nodesMissing = loadBootstrapNodes(confMissing)
    check nodesMissing.len == 0

  test "loadBootstrapNodes: deduplicates duplicate bootstrap nodes by peerId":
    let
      pid = getRandomPeerId()

      conf = NetworkConfig(
        bootstrapNodes: @[
        "/ip4/127.0.0.1/udp/9001/quic-v1/p2p/" & $pid,
        "/ip4/127.0.0.1/udp/9001/quic-v1/p2p/" & $pid,
        "/ip4/127.0.0.2/udp/9002/quic-v1/p2p/" & $pid
        ]
        )
      parsedNodes = loadBootstrapNodes(conf)
    check:
      parsedNodes.len == 1
      parsedNodes[0][0] == pid

suite "Bootstrap link maintenance and disconnection":
  test "shouldDisconnectBootstrap: predicate boundaries":
    # Below target -> do not disconnect
    check:
      not shouldDisconnectBootstrap(
        peerPoolLen = 1, wantedPeers = 4, bootstrapPeersInPool = 1)
      not shouldDisconnectBootstrap(
        peerPoolLen = 3, wantedPeers = 4, bootstrapPeersInPool = 1)
      # At or above target, but all peers in pool are bootstrap nodes -> do not disconnect
      not shouldDisconnectBootstrap(
        peerPoolLen = 4, wantedPeers = 4, bootstrapPeersInPool = 4)
      not shouldDisconnectBootstrap(
        peerPoolLen = 6, wantedPeers = 4, bootstrapPeersInPool = 6)
      # At target with at least 1 non-bootstrap peer -> disconnect
      shouldDisconnectBootstrap(
        peerPoolLen = 4, wantedPeers = 4, bootstrapPeersInPool = 1)
      shouldDisconnectBootstrap(
        peerPoolLen = 4, wantedPeers = 4, bootstrapPeersInPool = 3)
      # Above target with non-bootstrap peers -> disconnect
      shouldDisconnectBootstrap(
      peerPoolLen = 8, wantedPeers = 4, bootstrapPeersInPool = 2)

  asyncTest "runBootstrapLinkMaintenanceTick: disconnects bootstrap peer when pool target is met":
    let
      bootNode = await startTestNode("bootstrap-node", maxPeers = 8)
      bootPid = bootNode.switch.peerInfo.peerId
      bootAddrStr = bootNode.fullAddress()
      clientNode = await startTestNode("client-node", @[bootAddrStr], maxPeers = 2)
    await clientNode.start()

    try:
      # Connect client to bootstrap peer
      let connected = await connectViaConnQueue(
        clientNode,
        bootNode.peerAddr(),
        alwaysAllowPeer,
        3.seconds
      )
      check:
        connected
        clientNode.switch.isConnected(bootPid)

      let bootPeer = clientNode.getPeer(bootPid)
      check:
        clientNode.peerPool.hasPeer(bootPid)
        bootPeer.connectionState == ConnectionState.Connected

      # With only 1 peer in pool (which is bootstrap) and wantedPeers=2 -> tick does not disconnect
      await runBootstrapLinkMaintenanceTick(clientNode)
      check:
        clientNode.switch.isConnected(bootPid)
        bootPeer.connectionState == ConnectionState.Connected

      # Add a second regular (non-bootstrap) peer to meet wantedPeers target (2)
      let
        regPid = getRandomPeerId()
        regPeer = clientNode.getPeer(regPid)
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
