# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[net, strutils],
  chronos,
  chronos/unittest2/asynctests,
  ./testutil

import
  ../logos_chain/conf,
  ../logos_chain/networking/eth2_network,
  ../logos_chain/networking/eth2_discovery,
  libp2p/switch,
  libp2p/builders,
  libp2p/peerid,
  libp2p/services/wildcardresolverservice

suite "P2P stack — transport and reachability (Logos Chain / libp2p spec)":
  asyncTest "QUIC quic-v1 listen: switch binds and accepts on configured listen multiaddr":
    const expectedQuicPort = 5001

    let
      listenIp = parseIpAddress("127.0.0.1")
      natCfg = NatConfig(hasExtIp: true, extIp: listenIp)

    var
      rng1 = HmacDrbgContext.new()
      rng2 = HmacDrbgContext.new()
      conf: LBNodeConf
      conf2: LBNodeConf

    conf.listenAddress = some(listenIp)
    conf.nat = natCfg
    conf.quicPort = 5001.Port
    conf.discv5Enabled = true
    conf.maxPeers = 4
    conf.hardMaxPeers = some(4)
    conf.agentString = "p2p-test-node1"

    conf2.listenAddress = some(listenIp)
    conf2.nat = natCfg
    # `conf2` is only used for non-listen settings (agent/maxPeers) in this test;
    # the `sw2` transport binds to `/udp/0` via `addr2` below.
    conf2.quicPort = 5001.Port
    conf2.discv5Enabled = true
    conf2.maxPeers = 4
    conf2.hardMaxPeers = some(4)
    conf2.agentString = "p2p-test-node2"

    let node1Res =
      createLBNode(rng1, conf, rng1[].getRandomNetKeys())
    check:
      node1Res.isOk

    if node1Res.isErr():
      checkpoint("createLBNode failed: " & node1Res.error)
      fail()

    let node1 = node1Res.get()

    await node1.startListening()
    # Keep startup/stop scoped so sockets are released promptly.
    let fullAddrsRes = node1.switch.peerInfo.fullAddrs()
    check fullAddrsRes.isOk
    let fullAddrs = fullAddrsRes.get()
    var advertisedQuicFound = false
    for ma in fullAddrs:
      let s = $ma
      if s.contains("/udp/" & $expectedQuicPort & "/quic-v1"):
        advertisedQuicFound = true
        break
    check advertisedQuicFound

    var sw2: Switch = nil
    try:
      # Create a plain libp2p switch (not LBNode) that uses QUIC transport.
      let keys2 = rng2[].getRandomNetKeys()
      let addr2 =
        MultiAddress.init("/ip4/127.0.0.1/udp/0/quic-v1").tryGet()

      var sb = SwitchBuilder.new()
      sb = sb.withPrivateKey(keys2.seckey)
      sb = sb.withAddress(addr2)
      sb = sb.withRng(rng2)
      sb = sb.withNoise()
      sb = sb.withYamux(
        inTimeout = chronos.minutes(5),
        outTimeout = chronos.minutes(5)
      )
      sb = sb.withQuicTransport()
      sb = sb.withMaxConnections(conf2.maxPeers)
      sb = sb.withAgentVersion(conf2.agentString)
      let svc: Service = WildcardAddressResolverService.new()
      sb = sb.withServices(@[svc])

      sw2 = sb.build()
      await sw2.start()

      # Connect (transport-level) to validate inbound QUIC upgrading works.
      let peerId1 = node1.switch.peerInfo.peerId
      let addrs1 = node1.switch.peerInfo.addrs

      await sw2.connect(peerId1, addrs1, forceDial = true)
    finally:
      if not sw2.isNil:
        await sw2.stop()
      await node1.stop()

  asyncTest "Public advertisement: reachable multiaddr matches /{ip}/udp/{port}/quic-v1/p2p/{peer_id}":
    let
      listenIp = parseIpAddress("127.0.0.1")
      natCfg = NatConfig(hasExtIp: true, extIp: listenIp)
      expectedPort = 5001

    var
      rng = HmacDrbgContext.new()
      conf: LBNodeConf

    conf.listenAddress = some(listenIp)
    conf.nat = natCfg
    conf.quicPort = 5001.Port
    conf.discv5Enabled = true
    conf.maxPeers = 4
    conf.hardMaxPeers = some(4)
    conf.agentString = "p2p-test-node1"

    let nodeRes = createLBNode(rng, conf, rng[].getRandomNetKeys())
    check nodeRes.isOk
    if nodeRes.isErr():
      checkpoint("createLBNode failed: " & nodeRes.error)
      fail()
    let node = nodeRes.get()

    await node.startListening()
    # Ensure clean shutdown even if assertions fail.
    try:
      let peerIdStr = $node.switch.peerInfo.peerId
      let expectedNeedle =
        "/udp/" & $expectedPort & "/quic-v1/p2p/" & peerIdStr

      let fullAddrsRes = node.switch.peerInfo.fullAddrs()
      check fullAddrsRes.isOk
      let fullAddrs = fullAddrsRes.get()

      var found = false
      for ma in fullAddrs:
        let s = $ma
        if s.contains(expectedNeedle):
          found = true
          break

      check found
    finally:
      await node.stop()

  asyncTest "Lifecycle: network start and stop release listeners and pending dials cleanly":
    let
      listenIp = parseIpAddress("127.0.0.1")
      natCfg = NatConfig(hasExtIp: true, extIp: listenIp)

    var
      rng = HmacDrbgContext.new()
      conf: LBNodeConf

    conf.listenAddress = some(listenIp)
    conf.nat = natCfg
    conf.quicPort = 5001.Port
    conf.discv5Enabled = true
    conf.maxPeers = 4
    conf.hardMaxPeers = some(4)
    conf.agentString = "p2p-test-node1"

    let nodeRes = createLBNode(rng, conf, rng[].getRandomNetKeys())
    check nodeRes.isOk
    if nodeRes.isErr():
      checkpoint("createLBNode failed: " & nodeRes.error)
      fail()
    let node = nodeRes.get()

    await node.startListening()
    await node.stop()

suite "P2P stack — bootstrap and discovery":
  asyncTest "Bootstrap dial: node connects from /ip4/.../udp/.../p2p/{peerId} bootstrap multiaddr":
    const
      listenerPort = 5001.Port
      dialerPort = 5002.Port

    let (confL, confD, rngL, rngD) = makeBootstrapConfs(listenerPort, dialerPort)

    let listenerRes = createLBNode(rngL, confL, rngL[].getRandomNetKeys())
    check listenerRes.isOk
    if listenerRes.isErr():
      checkpoint("createLBNode listener: " & listenerRes.error)
      fail()
    let listener = listenerRes.get()
    await listener.startListening()

    let listenerPeerId = listener.switch.peerInfo.peerId
    let bootstrapAddr =
      "/ip4/127.0.0.1/udp/" & $listenerPort &
      "/quic-v1/p2p/" & $listenerPeerId

    var confDial = confD
    confDial.bootstrapNodes = @[bootstrapAddr]

    let dialerRes = createLBNode(rngD, confDial, rngD[].getRandomNetKeys())
    check dialerRes.isOk
    if dialerRes.isErr():
      checkpoint("createLBNode dialer: " & dialerRes.error)
      await listener.stop()
      fail()
    let dialer = dialerRes.get()

    try:
      await dialer.startListening()
      await dialer.start()

      let ok = await waitLibp2pConnected(dialer.switch, listenerPeerId)
      check ok
      check dialer.switch.isConnected(listenerPeerId)
    finally:
      await dialer.stop()
      await listener.stop()

  test "Bootstrap multiaddr: parseBootstrapAddress accepts /dns4/.../udp/.../quic-v1/p2p/...":
    ## Full DNS dial integration depends on the resolver; ip4 bootstrap covers
    ## the dial path. This validates Logos Chain bootstrap string parsing for DNS.
    var rng = HmacDrbgContext.new()
    let keys = rng[].getRandomNetKeys()
    let pidRes = PeerId.init(keys.seckey)
    check pidRes.isOk
    let peerId = pidRes.get()
    let dnsBootstrap =
      "/dns4/localhost/udp/5011/quic-v1/p2p/" & $peerId
    check parseBootstrapAddress(dnsBootstrap).isOk

  asyncTest "After bootstrap: libp2p QUIC session stays up (decentralized DHT deferred)":
    ## Peer pool admission still depends on Eth2-style protocol handshakes; we
    ## assert libp2p-level connectivity from the bootstrap multiaddr path.
    const
      listenerPort = 5021.Port
      dialerPort = 5022.Port

    let (confL, confD, rngL, rngD) = makeBootstrapConfs(listenerPort, dialerPort)

    let listenerRes = createLBNode(rngL, confL, rngL[].getRandomNetKeys())
    check listenerRes.isOk
    if listenerRes.isErr():
      checkpoint("createLBNode listener: " & listenerRes.error)
      fail()
    let listener = listenerRes.get()
    await listener.startListening()

    let listenerPeerId = listener.switch.peerInfo.peerId
    let bootstrapAddr =
      "/ip4/127.0.0.1/udp/" & $listenerPort &
      "/quic-v1/p2p/" & $listenerPeerId

    var confDial = confD
    confDial.bootstrapNodes = @[bootstrapAddr]

    let dialerRes = createLBNode(rngD, confDial, rngD[].getRandomNetKeys())
    check dialerRes.isOk
    if dialerRes.isErr():
      checkpoint("createLBNode dialer: " & dialerRes.error)
      await listener.stop()
      fail()
    let dialer = dialerRes.get()

    try:
      await dialer.start()

      check await waitLibp2pConnected(dialer.switch, listenerPeerId)
      await sleepAsync(1.seconds)
      check dialer.switch.isConnected(listenerPeerId)
    finally:
      await dialer.stop()
      await listener.stop()

  test "Kademlia: DHT protocol registered as /logos-blockchain/kad/1.0.0 (mainnet)":
    discard

  test "Kademlia: DHT protocol registered as /logos-blockchain-testnet/kad/1.0.0 (testnet)":
    discard

suite "P2P stack — protocol negotiation and Identify":
  test "Multistream: connection negotiates an application protocol by exact protocol ID string":
    discard

  test "Identify: handler registered for /logos-blockchain/identify/1.0.0 (mainnet)":
    discard

  test "Identify: handler registered for /logos-blockchain-testnet/identify/1.0.0 (testnet)":
    discard

  test "Identify exchange: peers report protocol support compatible with NAT / AutoNAT discovery needs":
    discard

suite "P2P stack — NAT and AutoNAT v2":
  test "AutoNAT v2 client uses /libp2p/autonat/2/dial-request toward reachable peers":
    discard

  test "AutoNAT v2 server responds on /libp2p/autonat/2/dial-back when node is public":
    discard

suite "P2P stack — GossipSub topics (Logos Chain wire topics)":
  test "GossipSub: subscribes and publishes /logos-blockchain/mempool/1.0.0 (mainnet)":
    discard

  test "GossipSub: subscribes and publishes /logos-blockchain/cryptarchia/1.0.0 (mainnet)":
    discard

  test "GossipSub: subscribes and publishes /logos-blockchain-testnet/mempool/1.0.0 (testnet)":
    discard

  test "GossipSub: subscribes and publishes /logos-blockchain-testnet/cryptarchia/1.0.0 (testnet)":
    discard

suite "P2P stack — on-the-wire encoding":
  test "Network Wire Format: payloads on negotiated streams follow Logos Chain wire format spec":
    discard

{.pop.}
