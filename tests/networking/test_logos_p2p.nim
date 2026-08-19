# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[net, sequtils, strutils],
  bearssl/rand,
  chronos,
  chronos/unittest2/asynctests,
  libp2p/[switch, builders, multiaddress, peerid],
  libp2p/protocols/connectivity/autonatv2/[types, client],
  ../testutil,
  ../../logos_chain/conf,
  ../../logos_chain/networking/[network, discovery]

from libp2p/protocols/connectivity/autonat/types import NetworkReachability

const autonatV2DialBackProto = $AutonatV2Codec.DialBack

proc autonatV2ClientOf(node: LBP2PNode): AutonatV2Client =
  let i = node.switch.ms.handlers.findIt(it.protocol.codec == autonatV2DialBackProto)
  doAssert i >= 0, "AutonatV2Client not mounted on LBP2PNode"
  AutonatV2Client(node.switch.ms.handlers[i].protocol)

suite "P2P stack — transport and reachability (Logos Chain / libp2p spec)":
  asyncTest "QUIC quic-v1 listen: switch binds and accepts on configured listen multiaddr":
    let
      listenIp = parseIpAddress("127.0.0.1")
      natCfg = nat.NatConfig(hasExtIp: true, extIp: listenIp)

    var
      rng1 = HmacDrbgContext.new()
      rng2 = HmacDrbgContext.new()

    let net1 = NetworkConfig(
      listenAddress: some(listenIp),
      nat: natCfg,
      quicPort: TestQuicAnyPort,
      maxPeers: 4,
      hardMaxPeers: some(4),
      agentString: "p2p-test-node1",
    )

    let net2 = NetworkConfig(
      listenAddress: some(listenIp),
      nat: natCfg,
      quicPort: TestQuicAnyPort,
      maxPeers: 4,
      hardMaxPeers: some(4),
      agentString: "p2p-test-node2",
    )

    let node1 = await startLBP2PNodeListening(
      rng1, net1, rng1.getRandomNetKeys(),
    )
    # Keep startup/stop scoped so sockets are released promptly.
    let listenMa = $node1.switch.peerInfo.listenAddrs[0]
    let fullAddrs = node1.switch.peerInfo.fullAddrs().valueOr:
      fail("peerInfo.fullAddrs failed: " & $error)
    var advertisedQuicFound = false
    for ma in fullAddrs:
      if ($ma).contains(listenMa):
        advertisedQuicFound = true
        break
    check advertisedQuicFound

    var sw2: Switch = nil
    try:
      # Create a plain libp2p switch (not LBNode) that uses QUIC transport.
      let keys2 = rng2.getRandomNetKeys()
      let listenAddr = MultiAddress.init(loopbackQuicMultiAddr(TestQuicAnyPort)).tryGet()
      var sb = SwitchBuilder.new()
      sb = sb.withPrivateKey(keys2.seckey)
      sb = sb.withAddress(listenAddr)
      sb = sb.withWildcardResolver()
      sb = sb.withRng(newBearSslRng(rng2))
      sb = sb.withNoise()
      sb = sb.withQuicTransport()
      sb = sb.withMaxConnections(net2.maxPeers)
      sb = sb.withAgentVersion(net2.agentString)
      sw2 = sb.build()
      await sw2.start()

      # Connect (transport-level) to validate inbound QUIC upgrading works.
      let
        peerId1 = node1.switch.peerInfo.peerId
        addrs1 = node1.switch.peerInfo.addrs

      await sw2.connect(peerId1, addrs1, forceDial = true)
    finally:
      if not sw2.isNil:
        await sw2.stop()
      await node1.stop()

  asyncTest "Public advertisement: reachable multiaddr matches /{ip}/udp/{port}/quic-v1/p2p/{peer_id}":
    let
      listenIp = parseIpAddress("127.0.0.1")
      natCfg = nat.NatConfig(hasExtIp: true, extIp: listenIp)

    var rng = HmacDrbgContext.new()

    let net = NetworkConfig(
      listenAddress: some(listenIp),
      nat: natCfg,
      quicPort: TestQuicAnyPort,
      maxPeers: 4,
      hardMaxPeers: some(4),
      agentString: "p2p-test-node1",
    )

    let node = await startLBP2PNodeListening(
      rng, net, rng.getRandomNetKeys(),
    )
    # Ensure clean shutdown even if assertions fail.
    try:
      let
        peerIdStr = $node.switch.peerInfo.peerId
        listenMa = $node.switch.peerInfo.listenAddrs[0]
        fullAddrs = node.switch.peerInfo.fullAddrs().valueOr:
          fail("peerInfo.fullAddrs failed: " & $error)

      var found = false
      for ma in fullAddrs:
        let s = $ma
        if s.contains(listenMa) and s.contains("/p2p/" & peerIdStr):
          found = true
          break

      check found
    finally:
      await node.stop()

  asyncTest "Lifecycle: network start and stop release listeners and pending dials cleanly":
    let
      listenIp = parseIpAddress("127.0.0.1")
      natCfg = nat.NatConfig(hasExtIp: true, extIp: listenIp)

    var rng = HmacDrbgContext.new()

    let net = NetworkConfig(
      listenAddress: some(listenIp),
      nat: natCfg,
      quicPort: TestQuicAnyPort,
      maxPeers: 4,
      hardMaxPeers: some(4),
      agentString: "p2p-test-node1",
    )

    let node = await startLBP2PNodeListening(
      rng, net, rng.getRandomNetKeys(),
    )
    await node.stop()

suite "P2P stack — bootstrap and discovery":
  asyncTest "Bootstrap dial: node connects from /ip4/.../udp/.../p2p/{peerId} bootstrap multiaddr":
    let peers = await createBootstrapPeers()
    try:
      await peers.dialer.start()

      let ok = await waitLibp2pConnected(peers.dialer.switch, peers.listenerPeerId)
      check ok
      check peers.dialer.switch.isConnected(peers.listenerPeerId)
    finally:
      await peers.dialer.stop()
      await peers.listener.stop()

  test "Bootstrap multiaddr: loadBootstrapNodes accepts /dns4/.../udp/.../quic-v1/p2p/...":
    ## Full DNS dial integration depends on the resolver; ip4 bootstrap covers
    ## the dial path. This validates Logos Chain bootstrap string parsing for DNS.
    var rng = HmacDrbgContext.new()
    let
      keys = rng.getRandomNetKeys()
      peerId = PeerId.init(keys.seckey).valueOr:
        fail("PeerId.init failed: " & $error)
      dnsPort = Port(5011)
      dnsBootstrap =
        "/dns4/localhost/udp/" & $dnsPort & "/quic-v1/p2p/" & $peerId
      netCfg = NetworkConfig(bootstrapNodes: @[dnsBootstrap])
      nodes = loadBootstrapNodes(netCfg)
    check nodes.len == 1
    check nodes[0][0] == peerId

  asyncTest "After bootstrap: libp2p QUIC session stays up (decentralized DHT deferred)":
    ## Peer pool admission still depends on Eth2-style protocol handshakes; we
    ## assert libp2p-level connectivity from the bootstrap multiaddr path.
    let peers = await createBootstrapPeers()
    try:
      await peers.dialer.start()

      check await waitLibp2pConnected(peers.dialer.switch, peers.listenerPeerId)
      await sleepAsync(1.seconds)
      check peers.dialer.switch.isConnected(peers.listenerPeerId)
    finally:
      await peers.dialer.stop()
      await peers.listener.stop()

  test "Kademlia: DHT protocol registered as /logos-blockchain/kad/1.0.0 (mainnet)":
    # TODO(logos-chain-networking): implement Logos Kademlia wiring and assertions
    skip()

  test "Kademlia: DHT protocol registered as /logos-blockchain-testnet/kad/1.0.0 (testnet)":
    # TODO(logos-chain-networking): implement Logos Kademlia wiring and assertions
    skip()

suite "P2P stack — protocol negotiation and Identify":
  test "Multistream: connection negotiates an application protocol by exact protocol ID string":
    # TODO(logos-chain-networking): assert multistream-select (libp2p's protocol
    # negotiation layer) chooses the Logos protocol IDs (`/logos-blockchain/...`)
    # exactly as required by the Logos P2P spec.
    skip()

  test "Identify: handler registered for /logos-blockchain/identify/1.0.0 (mainnet)":
    # TODO(logos-chain-networking): verify Identify handler registration for mainnet ID
    skip()

  test "Identify: handler registered for /logos-blockchain-testnet/identify/1.0.0 (testnet)":
    # TODO(logos-chain-networking): verify Identify handler registration for testnet ID
    skip()

  test "Identify exchange: peers report protocol support compatible with NAT / AutoNAT discovery needs":
    # TODO(logos-chain-networking): cover Identify exchange behavior for AutoNAT needs
    skip()

suite "P2P stack — NAT and AutoNAT v2":
  asyncTest "AutoNAT v2: dial-request and dial-back prove loopback reachability":
    ## Bootstrap only checks QUIC; AutoNAT is the dialer asking the listener to
    ## dial-back to the dialer's advertised addrs (second QUIC session).
    let peers = await createBootstrapPeers()
    try:
      await peers.dialer.startListening()
      await peers.dialer.start()

      check await waitLibp2pConnected(peers.dialer.switch, peers.listenerPeerId)
      await peers.dialer.switch.peerInfo.update()

      let testAddrs = peers.dialer.switch.peerInfo.addrs
      check testAddrs.len > 0

      let resp = await autonatV2ClientOf(peers.dialer).sendDialRequest(
        peers.listenerPeerId, testAddrs)
      check resp.reachability == NetworkReachability.Reachable
      check resp.dialResp.status == ResponseStatus.Ok
      check resp.dialResp.dialStatus == Opt.some(DialStatus.Ok)
    finally:
      await peers.dialer.stop()
      await peers.listener.stop()

suite "P2P stack — GossipSub topics (Logos Chain wire topics)":
  test "GossipSub: subscribes and publishes /logos-blockchain/mempool/1.0.0 (mainnet)":
    # TODO(logos-chain-networking): wire mainnet mempool topic and assert behavior
    skip()

  test "GossipSub: subscribes and publishes /logos-blockchain/cryptarchia/1.0.0 (mainnet)":
    # TODO(logos-chain-networking): wire mainnet cryptarchia topic and assert behavior
    skip()

  test "GossipSub: subscribes and publishes /logos-blockchain-testnet/mempool/1.0.0 (testnet)":
    # TODO(logos-chain-networking): wire testnet mempool topic and assert behavior
    skip()

  test "GossipSub: subscribes and publishes /logos-blockchain-testnet/cryptarchia/1.0.0 (testnet)":
    # TODO(logos-chain-networking): wire testnet cryptarchia topic and assert behavior
    skip()

suite "P2P stack — on-the-wire encoding":
  test "Network Wire Format: payloads on negotiated streams follow Logos Chain wire format spec":
    # TODO(logos-chain-networking): implement Network Wire Format coverage
    skip()

{.pop.}
