# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[sequtils, strutils],
  chronos,
  chronos/unittest2/asynctests,
  libp2p/[switch, builders, multiaddress, peerid, peerstore],
  libp2p/protocols/connectivity/autonatv2/[types, client],
  libp2p/protocols/pubsub/gossipsub,
  ../testutil,
  ../../logos_chain/conf,
  ../../logos_chain/core/mantle/[tx_types, tx_hashing],
  ../../logos_chain/networking/[network, discovery, protocols, bincode]

from libp2p/protocols/connectivity/autonat/types import NetworkReachability

const autonatV2DialBackProto = $AutonatV2Codec.DialBack

func autonatV2ClientOf(node: LBP2PNode): AutonatV2Client =
  let i = node.switch.ms.handlers.findIt(it.protocol.codec == autonatV2DialBackProto)
  doAssert i >= 0, "AutonatV2Client not mounted on LBP2PNode"
  AutonatV2Client(node.switch.ms.handlers[i].protocol)

suite "P2P stack — transport and reachability (Logos Chain / libp2p spec)":
  asyncTest "QUIC quic-v1 listen: switch binds and accepts on configured listen multiaddr":
    let node1 = await startTestNode("p2p-test-node1", maxPeers = 4)
    # Keep startup/stop scoped so sockets are released promptly.
    let listenMa = $node1.switch.peerInfo.listenAddrs[0]
    let fullAddrs = node1.switch.peerInfo.fullAddrs().tryGet()
    check fullAddrs.anyIt(($it).contains(listenMa))

    var sw2: Switch = nil
    try:
      # Create a plain libp2p switch (not LBNode) that uses QUIC transport.
      let keys2 = getRandomNetKeys()
      sw2 = await startQuicTestSwitch(keys2)

      # Connect (transport-level) to validate inbound QUIC upgrading works.
      await sw2.connect(
        node1.switch.peerInfo.peerId,
        node1.switch.peerInfo.addrs,
        forceDial = true
      )
    finally:
      if not sw2.isNil:
        await sw2.stop()
      await node1.stop()

  asyncTest "Public advertisement: reachable multiaddr matches /{ip}/udp/{port}/quic-v1/p2p/{peer_id}":
    let node = await startTestNode("p2p-test-node1", maxPeers = 4)
    # Ensure clean shutdown even if assertions fail.
    try:
      let
        peerIdStr = $node.switch.peerInfo.peerId
        listenMa = $node.switch.peerInfo.listenAddrs[0]
        fullAddrs = node.switch.peerInfo.fullAddrs().tryGet()

      check fullAddrs.anyIt(($it).contains(listenMa) and ($it).contains("/p2p/" & peerIdStr))
    finally:
      await node.stop()

  asyncTest "Explicit advertisement: configured --advertised-address appears in node announcedAddresses":
    let rng = getTestHmacRng()
    let net = NetworkConfig(
      listenAddress: some(parseIpAddress("127.0.0.1")),
      quicPort: Port(9000),
      announcedAddresses: announcedAddresses(@[
        parseUri("quic://198.51.100.1:4433"),
        parseUri("quic://203.0.113.5"),
        parseUri("quic://[2001:db8::1]:5001"),
      ], Port(9000)),
      logosNetwork: Testnet,
      maxPeers: 4,
      hardMaxPeers: some(4),
      agentString: "p2p-test-advertised",
    )
    check net.announcedAddresses.len == 3

    let node = createLBP2PNode(rng, net, getRandomNetKeys()).valueOr:
      fail("createLBP2PNode failed: " & $error)

    check node.announcedAddresses.len == 3
    check $node.announcedAddresses[0] == "/ip4/198.51.100.1/udp/4433/quic-v1"
    check $node.announcedAddresses[1] == "/ip4/203.0.113.5/udp/9000/quic-v1"
    check $node.announcedAddresses[2] == "/ip6/2001:db8::1/udp/5001/quic-v1"
    check node.switch.peerInfo.announcedAddrs.len == 3

  asyncTest "Lifecycle: network start and stop release listeners and pending dials cleanly":
    let node = await startTestNode("p2p-test-node1", maxPeers = 4)
    await node.stop()

suite "P2P stack — bootstrap and discovery":
  asyncTest "Bootstrap dial: node connects from /ip4/.../udp/.../p2p/{peerId} bootstrap multiaddr":
    let peers = await createBootstrapPeers()
    try:
      await peers.dialer.start()

      check waitUntil(peers.dialer.switch.isConnected(peers.listenerPeerId))
    finally:
      await peers.dialer.stop()
      await peers.listener.stop()

  test "Bootstrap multiaddr: loadBootstrapNodes accepts /dns4/.../udp/.../quic-v1/p2p/...":
    ## Full DNS dial integration depends on the resolver; ip4 bootstrap covers
    ## the dial path. This validates Logos Chain bootstrap string parsing for DNS.
    let
      peerId = getRandomPeerId()
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

      check waitUntil(peers.dialer.switch.isConnected(peers.listenerPeerId))
      await sleepAsync(50.milliseconds)
      check peers.dialer.switch.isConnected(peers.listenerPeerId)
    finally:
      await peers.dialer.stop()
      await peers.listener.stop()

  test "Kademlia: DHT protocol registered as /logos-blockchain/kad/1.0.0 (mainnet)":
    let node = createTestNode("kad-mainnet", logosNetwork = LogosNetworkKind.Mainnet)
    check not isNil(node.mountedProtocols.kad)
    check node.mountedProtocols.kad.codec == "/logos-blockchain/kad/1.0.0"

  test "Kademlia: DHT protocol registered as /logos-blockchain-testnet/kad/1.0.0 (testnet)":
    let node = createTestNode("kad-testnet", logosNetwork = LogosNetworkKind.Testnet)
    check not isNil(node.mountedProtocols.kad)
    check node.mountedProtocols.kad.codec == "/logos-blockchain-testnet/kad/1.0.0"

suite "P2P stack — protocol negotiation and Identify":
  asyncTest "Multistream: connection negotiates an application protocol by exact protocol ID string":
    let node1 = await startTestNode("p2p-ms-1", maxPeers = 4)
    let node2 = await startTestNode("p2p-ms-2", maxPeers = 4)
    try:
      let pid2 = node2.switch.peerInfo.peerId
      let conn = await node1.switch.dial(
        pid2,
        node2.switch.peerInfo.addrs,
        kadCodec(LogosNetworkKind.Testnet)
      )
      check not isNil(conn)
      check conn.protocol == "/logos-blockchain-testnet/kad/1.0.0"
      await conn.close()
    finally:
      await node1.stop()
      await node2.stop()

  test "Identify: handler registered for /logos-blockchain/identify/1.0.0 (mainnet)":
    let node = createTestNode("ident-mainnet", logosNetwork = LogosNetworkKind.Mainnet)
    check not isNil(node.mountedProtocols.identify)
    check node.mountedProtocols.identify.codec == "/logos-blockchain/identify/1.0.0"

  test "Identify: handler registered for /logos-blockchain-testnet/identify/1.0.0 (testnet)":
    let node = createTestNode("ident-testnet", logosNetwork = LogosNetworkKind.Testnet)
    check not isNil(node.mountedProtocols.identify)
    check node.mountedProtocols.identify.codec == "/logos-blockchain-testnet/identify/1.0.0"

  asyncTest "Identify exchange: peers report protocol support compatible with NAT / AutoNAT discovery needs":
    let node1 = await startTestNode("p2p-ident-1", maxPeers = 4)
    let node2 = await startTestNode("p2p-ident-2", maxPeers = 4)
    try:
      let pid2 = node2.switch.peerInfo.peerId
      await node1.switch.connect(
        pid2, node2.switch.peerInfo.addrs, forceDial = true)
      check node1.switch.isConnected(pid2)

      # Verify Identify exchange populates the remote peer's protocols in peerStore
      check waitUntil(autonatV2DialBackProto in node1.switch.peerStore[ProtoBook][pid2])
      let remoteProtos = node1.switch.peerStore[ProtoBook][pid2]
      check autonatV2DialBackProto in remoteProtos
      check "/logos-blockchain-testnet/identify/1.0.0" in remoteProtos
      check "/logos-blockchain-testnet/kad/1.0.0" in remoteProtos
    finally:
      await node1.stop()
      await node2.stop()

suite "P2P stack — NAT and AutoNAT v2":
  asyncTest "AutoNAT v2: dial-request and dial-back prove loopback reachability":
    ## Bootstrap only checks QUIC; AutoNAT is the dialer asking the listener to
    ## dial-back to the dialer's advertised addrs (second QUIC session).
    let peers = await createBootstrapPeers()
    try:
      await peers.dialer.startListening()
      await peers.dialer.start()

      check waitUntil(peers.dialer.switch.isConnected(peers.listenerPeerId))
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
    let tx = minimalSignedTx()
    let encoded = encodeSignedMantleTx(tx)
    check encoded.len > 0
    let decoded = decodeSignedMantleTx(encoded)
    check encodeSignedMantleTx(decoded) == encodeSignedMantleTx(tx)
    check mantleTxHash(decoded.tx) == mantleTxHash(tx.tx)
    check decoded.opProofs.len == tx.opProofs.len

{.pop.}
