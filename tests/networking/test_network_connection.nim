# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[net, sets],
  bearssl/rand,
  chronos,
  chronos/unittest2/asynctests,
  ../testutil

import
  ../../logos_chain/conf,
  ../../logos_chain/networking/network,
  eth/net/nat,
  libp2p/[switch, peerid, multiaddress]

suite "Network connection state — connTable, connQueue, dialTable, seenTable":
  asyncTest "tryEnqueueOutboundConn: eligible peer is reserved and queued once":
    let rng = HmacDrbgContext.new()
    let conf = NetworkConfig(
      listenAddress: some(TestLoopbackIp),
      nat: nat.NatConfig(hasExtIp: true, extIp: TestLoopbackIp),
      quicPort: TestQuicAnyPort,
      maxPeers: 16,
      hardMaxPeers: some(16),
      agentString: "try-enqueue-unit",
    )
    let node = createLBP2PNode(
      rng, conf, rng.getRandomNetKeys()
    ).expect("createLBP2PNode failed for try-enqueue-unit")

    let keys = node.rng.getRandomNetKeys()
    let pid = PeerId.init(keys.seckey).tryGet()
    let ma = MultiAddress.init("/ip4/127.0.0.1/udp/4333/quic-v1").tryGet()
    let pa = PeerAddr(peerId: pid, addrs: @[ma])

    check await tryEnqueueOutboundConn(
      node, pa, proc(p: PeerAddr): bool = true)
    check node.connTableContains(pid)
    check node.outboundConnQueueLen == 1
    check not await tryEnqueueOutboundConn(
      node, pa, proc(p: PeerAddr): bool = true)

  asyncTest "tryEnqueueOutboundConn: ineligible peer does not touch connTable":
    let rng = HmacDrbgContext.new()
    let conf = NetworkConfig(
      listenAddress: some(TestLoopbackIp),
      nat: nat.NatConfig(hasExtIp: true, extIp: TestLoopbackIp),
      quicPort: TestQuicAnyPort,
      maxPeers: 16,
      hardMaxPeers: some(16),
      agentString: "try-enqueue-ineligible",
    )
    let node = createLBP2PNode(
      rng, conf, rng.getRandomNetKeys()
    ).expect("createLBP2PNode failed for try-enqueue-ineligible")

    let keys = node.rng.getRandomNetKeys()
    let pid = PeerId.init(keys.seckey).tryGet()
    let ma = MultiAddress.init("/ip4/127.0.0.1/udp/4334/quic-v1").tryGet()
    let pa = PeerAddr(peerId: pid, addrs: @[ma])

    check not await tryEnqueueOutboundConn(
      node, pa, proc(p: PeerAddr): bool = false)
    check not node.connTableContains(pid)
    check node.outboundConnQueueLen == 0

  asyncTest "tryEnqueueOutboundConn: CancelledError rolls back connTable":
    ## ``connQueue`` is bounded (``ConcurrentConnections`` in network). Fill it so the
    ## next ``addLast`` blocks; cancelling that future must unwind and ``excl`` the id.
    const queueCap = 20
    let rng = HmacDrbgContext.new()
    let conf = NetworkConfig(
      listenAddress: some(TestLoopbackIp),
      nat: nat.NatConfig(hasExtIp: true, extIp: TestLoopbackIp),
      quicPort: TestQuicAnyPort,
      maxPeers: 16,
      hardMaxPeers: some(16),
      agentString: "try-enqueue-cancel",
    )
    let node = createLBP2PNode(
      rng, conf, rng.getRandomNetKeys()
    ).expect("createLBP2PNode failed for try-enqueue-cancel")

    let ma = MultiAddress.init("/ip4/127.0.0.1/udp/4335/quic-v1").tryGet()
    var seenIds: HashSet[PeerId]
    for _ in 0 ..< queueCap:
      var pid: PeerId
      while true:
        let keys = node.rng.getRandomNetKeys()
        pid = PeerId.init(keys.seckey).tryGet()
        if pid notin seenIds:
          seenIds.incl(pid)
          break
      let pa = PeerAddr(peerId: pid, addrs: @[ma])
      check await tryEnqueueOutboundConn(
        node, pa, proc(p: PeerAddr): bool = true)
    check node.outboundConnQueueLen == queueCap

    var pidBlocked: PeerId
    while true:
      let keysLast = node.rng.getRandomNetKeys()
      pidBlocked = PeerId.init(keysLast.seckey).tryGet()
      if pidBlocked notin seenIds:
        break
    let paBlocked = PeerAddr(peerId: pidBlocked, addrs: @[ma])
    let fut = tryEnqueueOutboundConn(
      node, paBlocked, proc(p: PeerAddr): bool = true)
    await sleepAsync(chronos.milliseconds(10))
    fut.cancelSoon()
    var gotCancelled = false
    try:
      discard await fut
    except CancelledError:
      gotCancelled = true
    check gotCancelled
    check not node.connTableContains(pidBlocked)

  asyncTest "connectViaConnQueue: bootstrap-style integration connects a live peer":
    let rngL = HmacDrbgContext.new()
    let rngD = HmacDrbgContext.new()
    let natCfg = nat.NatConfig(hasExtIp: true, extIp: TestLoopbackIp)

    let confL = NetworkConfig(
      listenAddress: some(TestLoopbackIp),
      nat: natCfg,
      quicPort: TestQuicAnyPort,
      maxPeers: 8,
      hardMaxPeers: some(8),
      agentString: "p2p-bootstrap-listener",
    )
    let confD = NetworkConfig(
      listenAddress: some(TestLoopbackIp),
      nat: natCfg,
      quicPort: TestQuicAnyPort,
      maxPeers: 8,
      hardMaxPeers: some(8),
      agentString: "p2p-bootstrap-dialer",
      bootstrapNodes: @[],
    )

    let listener = createLBP2PNode(
      rngL, confL, rngL.getRandomNetKeys()
    ).expect("createLBP2PNode failed for p2p-bootstrap-listener")
    let dialer = createLBP2PNode(
      rngD, confD, rngD.getRandomNetKeys()
    ).expect("createLBP2PNode failed for p2p-bootstrap-dialer")

    await listener.startListening()
    await dialer.startListening()
    await dialer.start()

    try:
      let listenerPeerAddr =
        PeerAddr(
          peerId: listener.switch.peerInfo.peerId,
          addrs: listener.switch.peerInfo.addrs
        )
      let connected =
        await connectViaConnQueue(
          dialer,
          listenerPeerAddr,
          proc(_: PeerAddr): bool {.gcsafe, raises: [].} = true,
          3.seconds
        )
      check connected
      check dialer.switch.isConnected(listenerPeerAddr.peerId)
    finally:
      await dialer.stop()
      await listener.stop()

  asyncTest "connectViaConnQueue: timeout marks peer seen and does not hang":
    let rng = HmacDrbgContext.new()
    let conf = NetworkConfig(
      listenAddress: some(TestLoopbackIp),
      nat: nat.NatConfig(hasExtIp: true, extIp: TestLoopbackIp),
      quicPort: TestQuicAnyPort,
      maxPeers: 8,
      hardMaxPeers: some(8),
      agentString: "connect-via-queue-timeout",
    )
    let node = createLBP2PNode(
      rng, conf, rng.getRandomNetKeys()
    ).expect("createLBP2PNode failed for connect-via-queue-timeout")
    node.setConnectTimeout(150.milliseconds)
    await node.startListening()
    await node.start()

    try:
      let deadKeys = node.rng.getRandomNetKeys()
      let deadPid = PeerId.init(deadKeys.seckey).tryGet()
      let deadAddr = MultiAddress.init("/ip4/127.0.0.1/udp/6551/quic-v1").tryGet()
      let fut =
        connectViaConnQueue(
          node,
          PeerAddr(peerId: deadPid, addrs: @[deadAddr]),
          proc(_: PeerAddr): bool {.gcsafe, raises: [].} = true,
          150.milliseconds
        )
      check await withTimeout(fut, 2.seconds)
      check not await fut
      check node.seenTableContains(deadPid)
    finally:
      await node.stop()

  asyncTest "connectWorker: in-flight dial appears in dialTable and clears after failure":
    let rng = HmacDrbgContext.new()
    let conf = NetworkConfig(
      listenAddress: some(TestLoopbackIp),
      nat: nat.NatConfig(hasExtIp: true, extIp: TestLoopbackIp),
      quicPort: TestQuicAnyPort,
      maxPeers: 8,
      hardMaxPeers: some(8),
      agentString: "connecting-peers-state",
    )
    let node = createLBP2PNode(
      rng, conf, rng.getRandomNetKeys()
    ).expect("createLBP2PNode failed for connecting-peers-state")
    node.setConnectTimeout(250.milliseconds)
    await node.startListening()
    await node.start()

    let deadKeys = node.rng.getRandomNetKeys()
    let deadPid = PeerId.init(deadKeys.seckey).tryGet()
    let deadAddr = MultiAddress.init("/ip4/192.0.2.1/udp/6552/quic-v1").tryGet()

    try:
      let fut =
        connectViaConnQueue(
          node,
          PeerAddr(peerId: deadPid, addrs: @[deadAddr]),
          proc(_: PeerAddr): bool {.gcsafe, raises: [].} = true,
          500.milliseconds
        )

      var sawConnecting = false
      for _ in 0 ..< 50:
        if node.dialTableContains(deadPid) or node.seenTableContains(deadPid):
          sawConnecting = true
          break
        await sleepAsync(chronos.milliseconds(5))
      check sawConnecting

      check not await fut

      var sawFailure = false
      for _ in 0 ..< 300:
        if node.seenTableContains(deadPid):
          sawFailure = true
          break
        await sleepAsync(chronos.milliseconds(10))
      check sawFailure

      var cleared = false
      for _ in 0 ..< 300:
        if not node.dialTableContains(deadPid):
          cleared = true
          break
        await sleepAsync(chronos.milliseconds(10))
      check cleared
    finally:
      await node.stop()

{.pop.}
