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
  chronos,
  chronos/unittest2/asynctests,
  ./testutil

import
  ../logos_chain/conf,
  ../logos_chain/networking/network,
  ../logos_chain/networking/discovery,
  libp2p/switch,
  libp2p/builders,
  libp2p/multiaddress,
  libp2p/peerid,
  libp2p/services/wildcardresolverservice,
  libp2p/protocols/connectivity/autonatv2/types,
  libp2p/protocols/connectivity/autonatv2/client

from libp2p/protocols/connectivity/autonat/types import NetworkReachability

const autonatV2DialBackProto = $AutonatV2Codec.DialBack

proc autonatV2ClientOf(node: LBP2PNode): AutonatV2Client =
  let i = node.switch.ms.handlers.findIt(it.protocol.codec == autonatV2DialBackProto)
  if i < 0:
    raiseAssert "AutonatV2Client not mounted on LBP2PNode"
  AutonatV2Client(node.switch.ms.handlers[i].protocol)

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
      createLBP2PNode(rng1, conf, rng1[].getRandomNetKeys())
    check:
      node1Res.isOk

    if node1Res.isErr():
      checkpoint("createLBP2PNode failed: " & node1Res.error)
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
      let
        keys2 = rng2[].getRandomNetKeys()
        addr2 =
          MultiAddress.init("/ip4/127.0.0.1/udp/0/quic-v1").tryGet()

      var sb = SwitchBuilder.new()
      sb = sb.withPrivateKey(keys2.seckey)
      sb = sb.withAddress(addr2)
      sb = sb.withRng(rng2)
      sb = sb.withNoise()
      sb = sb.withQuicTransport()
      sb = sb.withMaxConnections(conf2.maxPeers)
      sb = sb.withAgentVersion(conf2.agentString)
      let svc: Service = WildcardAddressResolverService.new()
      sb = sb.withServices(@[svc])

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

    let nodeRes = createLBP2PNode(rng, conf, rng[].getRandomNetKeys())
    check nodeRes.isOk
    if nodeRes.isErr():
      checkpoint("createLBP2PNode failed: " & nodeRes.error)
      fail()
    let node = nodeRes.get()

    await node.startListening()
    # Ensure clean shutdown even if assertions fail.
    try:
      let
        peerIdStr = $node.switch.peerInfo.peerId
        expectedNeedle =
          "/udp/" & $expectedPort & "/quic-v1/p2p/" & peerIdStr

        fullAddrsRes = node.switch.peerInfo.fullAddrs()
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

    let nodeRes = createLBP2PNode(rng, conf, rng[].getRandomNetKeys())
    check nodeRes.isOk
    if nodeRes.isErr():
      checkpoint("createLBP2PNode failed: " & nodeRes.error)
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

    let listenerRes = createLBP2PNode(rngL, confL, rngL[].getRandomNetKeys())
    check listenerRes.isOk
    if listenerRes.isErr():
      checkpoint("createLBP2PNode listener: " & listenerRes.error)
      fail()
    let listener = listenerRes.get()
    await listener.startListening()

    let
      listenerPeerId = listener.switch.peerInfo.peerId
      bootstrapAddr =
        "/ip4/127.0.0.1/udp/" & $listenerPort &
      "/quic-v1/p2p/" & $listenerPeerId

    var confDial = confD
    confDial.bootstrapNodes = @[bootstrapAddr]

    let dialerRes = createLBP2PNode(rngD, confDial, rngD[].getRandomNetKeys())
    check dialerRes.isOk
    if dialerRes.isErr():
      checkpoint("createLBP2PNode dialer: " & dialerRes.error)
      await listener.stop()
      fail()
    let dialer = dialerRes.get()

    try:
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
    let
      keys = rng[].getRandomNetKeys()
      pidRes = PeerId.init(keys.seckey)
    check pidRes.isOk
    let
      peerId = pidRes.get()
      dnsBootstrap =
        "/dns4/localhost/udp/5011/quic-v1/p2p/" & $peerId
    check parseBootstrapAddress(dnsBootstrap).isOk

  asyncTest "After bootstrap: libp2p QUIC session stays up (decentralized DHT deferred)":
    ## Peer pool admission still depends on Eth2-style protocol handshakes; we
    ## assert libp2p-level connectivity from the bootstrap multiaddr path.
    const
      listenerPort = 5021.Port
      dialerPort = 5022.Port

    let (confL, confD, rngL, rngD) = makeBootstrapConfs(listenerPort, dialerPort)

    let listenerRes = createLBP2PNode(rngL, confL, rngL[].getRandomNetKeys())
    check listenerRes.isOk
    if listenerRes.isErr():
      checkpoint("createLBP2PNode listener: " & listenerRes.error)
      fail()
    let listener = listenerRes.get()
    await listener.startListening()

    let
      listenerPeerId = listener.switch.peerInfo.peerId
      bootstrapAddr =
        "/ip4/127.0.0.1/udp/" & $listenerPort &
      "/quic-v1/p2p/" & $listenerPeerId

    var confDial = confD
    confDial.bootstrapNodes = @[bootstrapAddr]

    let dialerRes = createLBP2PNode(rngD, confDial, rngD[].getRandomNetKeys())
    check dialerRes.isOk
    if dialerRes.isErr():
      checkpoint("createLBP2PNode dialer: " & dialerRes.error)
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
    const
      listenerPort = 5053.Port
      dialerPort = 5054.Port

    let (confL, confD, rngL, rngD) = makeBootstrapConfs(listenerPort, dialerPort)

    let listenerRes = createLBP2PNode(rngL, confL, rngL[].getRandomNetKeys())
    check listenerRes.isOk
    if listenerRes.isErr():
      checkpoint("createLBP2PNode listener: " & listenerRes.error)
      fail()
    let listener = listenerRes.get()
    await listener.startListening()

    let
      listenerPeerId = listener.switch.peerInfo.peerId
      bootstrapAddr =
        "/ip4/127.0.0.1/udp/" & $listenerPort &
        "/quic-v1/p2p/" & $listenerPeerId

    var confDial = confD
    confDial.bootstrapNodes = @[bootstrapAddr]

    let dialerRes = createLBP2PNode(rngD, confDial, rngD[].getRandomNetKeys())
    check dialerRes.isOk
    if dialerRes.isErr():
      checkpoint("createLBP2PNode dialer: " & dialerRes.error)
      await listener.stop()
      fail()
    let dialer = dialerRes.get()

    try:
      await dialer.startListening()
      await dialer.start()

      check await waitLibp2pConnected(dialer.switch, listenerPeerId)
      await dialer.switch.peerInfo.update()

      let testAddrs = dialer.switch.peerInfo.addrs
      check testAddrs.len > 0

      let resp = await autonatV2ClientOf(dialer).sendDialRequest(
        listenerPeerId, testAddrs)
      check resp.reachability == NetworkReachability.Reachable
      check resp.dialResp.status == ResponseStatus.Ok
      check resp.dialResp.dialStatus == Opt.some(DialStatus.Ok)
    finally:
      await dialer.stop()
      await listener.stop()

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
