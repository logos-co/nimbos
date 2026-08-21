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

suite "Network connection state — outboundTable, connQueue, seenTable":
  asyncTest "tryEnqueueOutboundConn: eligible peer is reserved in outboundTable (Queued) and queued once":
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
    check node.outboundStage(pid) == Opt.some(OutboundConnStage.Queued)
    check node.outboundConnQueueLen == 1
    check not await tryEnqueueOutboundConn(
      node, pa, proc(p: PeerAddr): bool = true)

  asyncTest "tryEnqueueOutboundConn: ineligible peer does not touch outboundTable":
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
    check node.outboundStage(pid).isNone
    check node.outboundConnQueueLen == 0

  asyncTest "tryEnqueueOutboundConn: CancelledError rolls back outboundTable":
    ## ``connQueue`` is bounded (``ConcurrentConnections`` in network). Fill it so the
    ## next ``addLast`` blocks; cancelling that future must unwind and delete from ``outboundTable``.
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
    check node.outboundStage(pidBlocked).isNone

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
    node.setConnectTimeout(50.milliseconds)
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
          1.seconds
        )
      check await withTimeout(fut, 2.seconds)
      check not await fut
      check node.seenTableContains(deadPid)
    finally:
      await node.stop()

  asyncTest "connectWorker: in-flight dial transitions to Dialing stage and clears after failure":
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
        if node.outboundStage(deadPid) == Opt.some(OutboundConnStage.Dialing) or node.seenTableContains(deadPid):
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
        if node.outboundStage(deadPid).isNone:
          cleared = true
          break
        await sleepAsync(chronos.milliseconds(10))
      check cleared
    finally:
      await node.stop()

  asyncTest "connectViaConnQueue: multiple concurrent callers coalesce and all resolve true":
    let rngL = HmacDrbgContext.new()
    let rngD = HmacDrbgContext.new()
    let natCfg = nat.NatConfig(hasExtIp: true, extIp: TestLoopbackIp)

    let confL = NetworkConfig(
      listenAddress: some(TestLoopbackIp),
      nat: natCfg,
      quicPort: TestQuicAnyPort,
      maxPeers: 8,
      hardMaxPeers: some(8),
      agentString: "p2p-coalesce-listener",
    )
    let confD = NetworkConfig(
      listenAddress: some(TestLoopbackIp),
      nat: natCfg,
      quicPort: TestQuicAnyPort,
      maxPeers: 8,
      hardMaxPeers: some(8),
      agentString: "p2p-coalesce-dialer",
      bootstrapNodes: @[],
    )

    let listener = createLBP2PNode(
      rngL, confL, rngL.getRandomNetKeys()
    ).expect("createLBP2PNode failed for p2p-coalesce-listener")
    let dialer = createLBP2PNode(
      rngD, confD, rngD.getRandomNetKeys()
    ).expect("createLBP2PNode failed for p2p-coalesce-dialer")

    await listener.startListening()
    await dialer.startListening()
    await dialer.start()

    try:
      let listenerPeerAddr =
        PeerAddr(
          peerId: listener.switch.peerInfo.peerId,
          addrs: listener.switch.peerInfo.addrs
        )
      let fut1 = connectViaConnQueue(
        dialer,
        listenerPeerAddr,
        proc(_: PeerAddr): bool {.gcsafe, raises: [].} = true,
        3.seconds
      )
      let fut2 = connectViaConnQueue(
        dialer,
        listenerPeerAddr,
        proc(_: PeerAddr): bool {.gcsafe, raises: [].} = true,
        3.seconds
      )
      let res1 = await fut1
      let res2 = await fut2
      check res1
      check res2
      check dialer.switch.isConnected(listenerPeerAddr.peerId)
    finally:
      await dialer.stop()
      await listener.stop()

  asyncTest "connected peers complete protocol handshake and are admitted to peerPool with Connected state":
    let rngL = HmacDrbgContext.new()
    let rngD = HmacDrbgContext.new()
    let natCfg = nat.NatConfig(hasExtIp: true, extIp: TestLoopbackIp)

    let confL = NetworkConfig(
      listenAddress: some(TestLoopbackIp),
      nat: natCfg,
      quicPort: TestQuicAnyPort,
      maxPeers: 8,
      hardMaxPeers: some(8),
      agentString: "p2p-pool-admission-listener",
    )
    let confD = NetworkConfig(
      listenAddress: some(TestLoopbackIp),
      nat: natCfg,
      quicPort: TestQuicAnyPort,
      maxPeers: 8,
      hardMaxPeers: some(8),
      agentString: "p2p-pool-admission-dialer",
      bootstrapNodes: @[],
    )

    let listener = createLBP2PNode(
      rngL, confL, rngL.getRandomNetKeys()
    ).expect("createLBP2PNode failed for p2p-pool-admission-listener")
    let dialer = createLBP2PNode(
      rngD, confD, rngD.getRandomNetKeys()
    ).expect("createLBP2PNode failed for p2p-pool-admission-dialer")

    await listener.startListening()
    await dialer.startListening()
    await listener.start()
    await dialer.start()

    try:
      let listenerPeerAddr =
        PeerAddr(
          peerId: listener.switch.peerInfo.peerId,
          addrs: listener.switch.peerInfo.addrs
        )
      check await connectViaConnQueue(
        dialer,
        listenerPeerAddr,
        proc(_: PeerAddr): bool {.gcsafe, raises: [].} = true,
        3.seconds
      )

      # 1. Verify Switch raw transport connection
      check dialer.switch.isConnected(listenerPeerAddr.peerId)

      # 2. Verify PeerPool admission via waitForPeers
      let readyPeers = await dialer.waitForPeers(minPeers = 1, timeout = 3.seconds)
      check readyPeers.len >= 1
      check listenerPeerAddr.peerId in readyPeers
      check dialer.peerPool.hasPeer(listenerPeerAddr.peerId)

      # 3. Verify Peer readiness state and score
      let peerInDialer = dialer.getPeer(listenerPeerAddr.peerId)
      check peerInDialer.connectionState == ConnectionState.Connected
      check peerInDialer.getScore == NewPeerScore
    finally:
      await dialer.stop()
      await listener.stop()

{.pop.}
