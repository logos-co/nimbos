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
  chronos,
  chronos/unittest2/asynctests,
  ../testutil

import
  ../../logos_chain/conf,
  ../../logos_chain/networking/network,
  libp2p/[switch, peerid, multiaddress]

suite "Network connection state — outboundTable, connQueue, seenTable":
  asyncTest "tryEnqueueOutboundConn: eligible peer is reserved in outboundTable (Queued) and queued once":
    let node = createTestNode("try-enqueue-unit")
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
    let node = createTestNode("try-enqueue-ineligible")
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
    let node = createTestNode("try-enqueue-cancel")

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
    let listener = await startTestNode("p2p-bootstrap-listener")
    let dialer = await startTestNode("p2p-bootstrap-dialer")

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
    let node = await startTestNode("connect-via-queue-timeout")
    node.setConnectTimeout(50.milliseconds)
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
    let node = await startTestNode("connecting-peers-state")
    node.setConnectTimeout(50.milliseconds)
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
          200.milliseconds
        )

      check waitUntil(
        node.outboundStage(deadPid) == Opt.some(OutboundConnStage.Dialing) or node.seenTableContains(deadPid)
      )

      check not await fut

      check waitUntil(node.seenTableContains(deadPid))
      check waitUntil(node.outboundStage(deadPid).isNone)
    finally:
      await node.stop()

  asyncTest "connectViaConnQueue: multiple concurrent callers coalesce and all resolve true":
    let listener = await startTestNode("p2p-coalesce-listener")
    let dialer = await startTestNode("p2p-coalesce-dialer")

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

  asyncTest "connected peers are admitted to peerPool with Connected state upon libp2p connection":
    let listener = await startTestNode("p2p-pool-admission-listener")
    let dialer = await startTestNode("p2p-pool-admission-dialer")

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

      # 2. Verify PeerPool admission
      check waitUntil(dialer.peerPool.hasPeer(listenerPeerAddr.peerId))
      check dialer.peerPool.hasPeer(listenerPeerAddr.peerId)

      # 3. Verify Peer readiness state and score
      let peerInDialer = dialer.getPeer(listenerPeerAddr.peerId)
      check peerInDialer.connectionState == ConnectionState.Connected
      check peerInDialer.getScore == NewPeerScore
    finally:
      await dialer.stop()
      await listener.stop()

  asyncTest "waitForBootstrapPeers: fast path returns immediately when all configured bootstrap peers connect":
    let listener1 = await startTestNode("p2p-fast-listener-1")
    let listener2 = await startTestNode("p2p-fast-listener-2")
    let dialer = await startTestNode(
      "p2p-fast-dialer",
      @[listener1.fullAddress(), listener2.fullAddress()],
    )

    try:
      await listener1.start()
      await listener2.start()
      await dialer.start()

      let startTime = Moment.now()
      let readyPeers = await dialer.waitForBootstrapPeers()
      let elapsed = Moment.now() - startTime

      # Fast path returns immediately as soon as all connect (< 5 seconds)
      check readyPeers.len == 2
      check listener1.switch.peerInfo.peerId in readyPeers
      check listener2.switch.peerInfo.peerId in readyPeers
      check elapsed < 5.seconds
    finally:
      await dialer.stop()
      await listener1.stop()
      await listener2.stop()

  asyncTest "waitForBootstrapPeers: grace period allows in-flight peers to settle without waiting full bootstrapTimeout":
    let listener = await startTestNode("p2p-grace-listener")
    let dialer = await startTestNode(
      "p2p-grace-dialer",
      @[listener.fullAddress(), DeadBootstrapAddress],
    )

    try:
      await listener.start()
      let waitFut = dialer.waitForBootstrapPeers()
      asyncSpawn dialer.start()

      let startTime = Moment.now()
      let readyPeers = await waitFut
      let elapsed = Moment.now() - startTime

      # 1. Verify that the live bootstrap peer connected and was returned
      check readyPeers == @[listener.switch.peerInfo.peerId]

      # 2. Verify grace period bounded elapsed time to ~300ms, well under 30s bootstrapTimeout
      check elapsed >= BootstrapDialGrace
      check elapsed < 5.seconds
    finally:
      await dialer.stop()
      await listener.stop()

  asyncTest "waitForBootstrapPeers: returns empty seq when no bootstrap peers connect within timeout":
    let dialer = await startTestNode(
      "p2p-timeout-dialer",
      @[DeadBootstrapAddress],
    )
    dialer.setConnectTimeout(10.milliseconds)
    dialer.bootstrapTimeout = 10.milliseconds

    try:
      let waitFut = dialer.waitForBootstrapPeers()
      asyncSpawn dialer.start()
      let startTime = Moment.now()
      let readyPeers = await waitFut
      let elapsed = Moment.now() - startTime

      check readyPeers.len == 0
      check elapsed >= 10.milliseconds
      check elapsed < 2.seconds
    finally:
      await dialer.stop()

{.pop.}
