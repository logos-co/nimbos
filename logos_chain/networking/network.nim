# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Std lib
  std/[sequtils, sets, algorithm, tables],

  # Vendor / external libs
  bearssl/rand,
  chronos, chronicles, metrics, results,
  stew/byteutils,
  eth/[async_utils, net/nat],
  libp2p/[switch, peerinfo, multiaddress, crypto/crypto, builders],
  libp2p/protocols/connectivity/autonatv2/[server, service],
  libp2p/protocols/pubsub/[pubsub, gossipsub, rpc/message, rpc/messages],
  libp2p/stream/connection,

  # Local networking modules
  ./[bincode, discovery, protocols, peer_pool, peer_scores],

  # Logos chain core modules
  ../[version, conf]

export
  tables, chronos, version, multiaddress, peerinfo,
  connection, bincode, results,
  discovery, protocols, peer_pool, peer_scores

logScope:
  topics = "networking"

type
  NetKeyPair* = crypto.KeyPair
  PublicKey = crypto.PublicKey
  PrivateKey = crypto.PrivateKey

  # TODO: This is here only to eradicate a compiler
  # warning about unused import (rpc/messages).
  GossipMsg = messages.Message

  ValidationSyncProc[T] =
    proc(msg: T, src: PeerId): ValidationResult {.gcsafe, raises: [].}

  ValidationAsyncProc[T] =
    proc(msg: T, src: PeerId): Future[ValidationResult] {.
      async: (raises: [CancelledError]).}

  SeenItem = object
    peerId: PeerId
    stamp: chronos.Moment

  OutboundConnStage* {.pure.} = enum
    Queued   ## Reserved in connQueue waiting for a worker
    Dialing  ## Popped from connQueue and actively executing switch.connect

  LBP2PNode* = ref object of RootObj
    switch*: Switch
    pubsub: GossipSub
    wantedPeers: int
    hardMaxPeers: int
    peerPool*: PeerPool[Peer, PeerId]
    connectTimeout: chronos.Duration
    connQueue: AsyncQueue[PeerAddr]
    seenTable: Table[PeerId, SeenItem]
    outboundTable: Table[PeerId, OutboundConnStage]
    connEvents: Table[PeerId, AsyncEvent]
    mountedProtocols*: MountedProtocols
    rng*: ref HmacDrbgContext
    peers: Table[PeerId, Peer]
    announcedAddresses*: seq[MultiAddress]
    bootstrapPeers: seq[PeerAddr]
    bootstrapTimeout*: chronos.Duration
    peerChangeEvent: AsyncEvent
    validTopics: HashSet[string]
    backgroundTasks: seq[Future[void].Raising([CancelledError])]

  Peer* = ref object
    network*: LBP2PNode
    peerId*: PeerId
    connectionState*: ConnectionState
    score: int
    connections: int
    direction: PeerType
    disconnectedFut: Future[void]

  PeerAddr* = object
    peerId*: PeerId
    addrs*: seq[MultiAddress]

  ConnectionState* {.pure.} = enum
    None,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected

  DisconnectionReason* {.pure.} = enum
    # might see other values on the wire!
    ClientShutDown = 1
    IrrelevantNetwork = 2
    FaultOrError = 3
    # Clients MAY use reason codes above 128 to indicate alternative,
    # erroneous request-specific responses.
    PeerScoreLow = 237 # 79 * 3

const
  clientId* = "Nimbos node " & fullVersionStr

  ConcurrentConnections = 20
    ## Maximum number of active concurrent connection requests.

  SeenTableTimeTimeout =
    when not defined(local_testnet): 5.minutes else: 10.seconds

    ## Seen period of time for timeout connections
  SeenTableTimeDeadPeer =
    when not defined(local_testnet): 5.minutes else: 10.seconds

  MAX_PAYLOAD_SIZE = 10000000

    ## Period of time for dead peers.
  SeenTableTimeIrrelevantNetwork = 24.hours
    ## Period of time for `IrrelevantNetwork` error reason.
  SeenTableTimeClientShutDown = 10.minutes
    ## Period of time for `ClientShutDown` error reason.
  SeenTableTimeFaultOrError = 10.minutes
    ## Period of time for `FaultOnError` error reason.
  SeenTablePenaltyError = 60.minutes
    ## Period of time for peers which score below or equal to zero.
  SeenTableTimeReconnect = 1.minutes
    ## Minimal time between disconnection and reconnection attempt

# Metrics for tracking network activity
declareCounter logos_p2p_gossip_messages_received,
  "Number of gossip messages received by this peer"

declareCounter logos_p2p_successful_dials,
  "Number of successfully dialed peers"

declareCounter logos_p2p_failed_dials,
  "Number of dialing attempts that failed"

declareCounter logos_p2p_timeout_dials,
  "Number of dialing attempts that exceeded timeout"

declareGauge logos_p2p_peers,
  "Number of active libp2p peers"

when not (crypto.PKScheme.Ed25519 in crypto.SupportedSchemes):
  {.fatal:
    "Incorrect building process, please use -d:\"libp2p_pki_schemes=ed25519\"".}

func shortLog*(peer: Peer): string = shortLog(peer.peerId)
chronicles.formatIt(Peer): shortLog(it)
chronicles.formatIt(PublicKey): byteutils.toHex(it.getBytes().tryGet())

proc init(T: type Peer, network: LBP2PNode, peerId: PeerId): Peer =
  Peer(
    peerId: peerId,
    network: network,
    connectionState: ConnectionState.None,
  )

func peerId*(node: LBP2PNode): PeerId =
  node.switch.peerInfo.peerId

proc getPeer*(node: LBP2PNode, peerId: PeerId): Peer =
  node.peers.withValue(peerId, peer) do:
    return peer[]
  do:
    let peer = Peer.init(node, peerId)
    return node.peers.mgetOrPut(peerId, peer)


template getKey*(peer: Peer): PeerId =
  ## Benchmark (10M ops): template (11.44 ms) vs default (94.46 ms) vs inline (95.83 ms).
  peer.peerId

proc getFuture*(peer: Peer): Future[void] {.inline.} =
  if isNil(peer.disconnectedFut):
    peer.disconnectedFut = newFuture[void]("Peer.disconnectedFut")
  peer.disconnectedFut

template getScore*(a: Peer): int =
  ## Returns current score value for peer ``peer``.
  ## Benchmark (50k x 50 sort): template (5.93 ms) vs default (5.97 ms) vs inline (5.97 ms).
  a.score


# /!\ Must be exported to be seen by `peerpool`.
func cmp*(a, b: Peer): int =
  cmp(a.score, b.score)



proc isSeen(network: LBP2PNode, peerId: PeerId): bool =
  ## Returns ``true`` if ``peerId`` present in SeenTable and time period is not
  ## yet expired.
  let currentTime = now(chronos.Moment)
  if peerId notin network.seenTable:
    false
  else:
    let item = try: network.seenTable[peerId]
    except KeyError: raiseAssert "checked with notin"
    if currentTime >= item.stamp:
      # Peer is in SeenTable, but the time period has expired.
      network.seenTable.del(peerId)
      false
    else:
      true

proc addSeen(network: LBP2PNode, peerId: PeerId,
              period: chronos.Duration) =
  ## Adds peer with PeerId ``peerId`` to SeenTable and timeout ``period``.
  let item = SeenItem(peerId: peerId, stamp: now(chronos.Moment) + period)
  withValue(network.seenTable, peerId, entry) do:
    if entry.stamp < item.stamp:
      entry.stamp = item.stamp
  do:
    network.seenTable[peerId] = item

proc disconnect*(peer: Peer, reason: DisconnectionReason,
                 notifyOtherPeer = false) {.async: (raises: [CancelledError]).} =
  # Per the specification, we MAY send a disconnect reason to the other peer but
  # we currently don't - the fact that we're disconnecting is obvious and the
  # reason already known (wrong network is known from status message) or doesn't
  # greatly matter for the listening side (since it can't be trusted anyway)
  # ``switch.disconnect`` only raises ``CancelledError``, which we let propagate.
  if peer.connectionState notin {ConnectionState.Disconnecting, ConnectionState.Disconnected}:
    peer.connectionState = ConnectionState.Disconnecting
    # We adding peer in SeenTable before actual disconnect to avoid races.
    let seenTime = case reason
      of ClientShutDown:
        SeenTableTimeClientShutDown
      of IrrelevantNetwork:
        SeenTableTimeIrrelevantNetwork
      of FaultOrError:
        SeenTableTimeFaultOrError
      of PeerScoreLow:
        SeenTablePenaltyError
    peer.network.addSeen(peer.peerId, seenTime)
    await peer.network.switch.disconnect(peer.peerId)

proc releasePeer(peer: Peer) =
  ## Checks for peer's score and disconnects peer if score is less than
  ## `PeerScoreLowLimit`.
  if peer.connectionState notin {ConnectionState.Disconnecting,
                                 ConnectionState.Disconnected}:
    if peer.score < PeerScoreLowLimit:
      debug "Peer was disconnected due to low score", peer = peer,
            peer_score = peer.score, score_low_limit = PeerScoreLowLimit,
            score_high_limit = PeerScoreHighLimit
      asyncSpawn(peer.disconnect(PeerScoreLow))

func outboundStage*(node: LBP2PNode, pid: PeerId): Opt[OutboundConnStage] {.inline.} =
  ## Benchmark (2M ops): inline (25.71 ms) vs template (26.24 ms) vs default (26.54 ms).
  node.outboundTable.withValue(pid, stage):
    return Opt.some(stage[])
  do:
    return Opt.none(OutboundConnStage)

proc checkPeer(node: LBP2PNode, peerAddr: PeerAddr): bool =
  logScope: peer = peerAddr.peerId
  let peerId = peerAddr.peerId
  if node.peerPool.hasPeer(peerId):
    trace "Already connected"
    false
  elif node.outboundStage(peerId) == Opt.some(OutboundConnStage.Dialing):
    trace "Dial already in progress"
    false
  else:
    if node.isSeen(peerId):
      trace "Recently connected"
      false
    else:
      true

proc tryEnqueueOutboundConn*(
    node: LBP2PNode,
    peerAddr: PeerAddr,
    isEligible: proc(peerAddr: PeerAddr): bool {.gcsafe, raises: [].},
): Future[bool] {.async: (raises: [CancelledError]).} =
  ## Reserve ``peerAddr.peerId`` in ``outboundTable`` (stage ``Queued``) and enqueue a dial.
  ## On ``CancelledError`` from ``addLast``, roll back the reservation. Takes ``LBP2PNode``
  ## (a ref) so the async closure can safely reach ``outboundTable`` / ``connQueue``.
  if not isEligible(peerAddr):
    return false
  let peerId = peerAddr.peerId
  if node.outboundTable.hasKeyOrPut(peerId, OutboundConnStage.Queued):
    return false
  try:
    await node.connQueue.addLast(peerAddr)
  except CancelledError as exc:
    node.outboundTable.del(peerId)
    raise exc
  return true

proc enqueueOutboundPeer(
    node: LBP2PNode, peerAddr: PeerAddr
): Future[bool] {.async: (raises: [CancelledError]).} =
  await tryEnqueueOutboundConn(
    node, peerAddr,
    proc(p: PeerAddr): bool {.gcsafe, raises: [].} =
      node.checkPeer(p))

proc enqueueBootstrapPeers(
    node: LBP2PNode
): Future[int] {.async: (raises: [CancelledError]).} =
  var count = 0
  for b in node.bootstrapPeers:
    if await node.enqueueOutboundPeer(b):
      inc count
  count

proc signalConnEvent(node: LBP2PNode, pid: PeerId) =
  node.connEvents.withValue(pid, event):
    event[].fire()
    node.connEvents.del(pid)

proc waitForOutboundDial(
    node: LBP2PNode, pid: PeerId, timeout: Duration
): Future[bool] {.async: (raises: [CancelledError]).} =
  if node.switch.isConnected(pid):
    return true
  if pid notin node.outboundTable:
    return false

  var event: AsyncEvent
  node.connEvents.withValue(pid, ev):
    event = ev[]
  do:
    event = newAsyncEvent()
    node.connEvents[pid] = event

  try:
    discard await withTimeout(event.wait(), timeout)
    return node.switch.isConnected(pid)
  finally:
    node.connEvents.withValue(pid, curEvent):
      if curEvent[] == event:
        node.connEvents.del(pid)

proc connectViaConnQueue*(
    node: LBP2PNode,
    peerAddr: PeerAddr,
    isEligible: proc(peerAddr: PeerAddr): bool {.gcsafe, raises: [].},
    waitTimeout: Duration,
): Future[bool] {.async: (raises: [CancelledError]).} =
  if node.switch.isConnected(peerAddr.peerId):
    return true

  let enqueued = await tryEnqueueOutboundConn(node, peerAddr, isEligible)
  if not enqueued and not node.switch.isConnected(peerAddr.peerId):
    # This call did not enqueue a dial, and we are still disconnected.
    # If ``outboundTable`` also has no reservation for this peer id, no other
    # caller/worker has an in-flight dial either, so waiting cannot succeed.
    if peerAddr.peerId notin node.outboundTable:
      return false

  return await waitForOutboundDial(
    node, peerAddr.peerId, waitTimeout)

proc dialPeer(node: LBP2PNode, peerAddr: PeerAddr, index = 0) {.async: (raises: [CancelledError]).} =
  ## Establish connection with remote peer identified by address ``peerAddr``.
  logScope:
    peer = peerAddr.peerId
    index = index

  debug "Connecting to discovered peer", addrs = peerAddr.addrs
  var deadline = sleepAsync(node.connectTimeout)
  var workfut = node.switch.connect(
    peerAddr.peerId,
    peerAddr.addrs,
    forceDial = true
  )

  try:
    # `or` operation will only raise exception of `workfut`, because `deadline`
    # could not raise exception.
    await workfut or deadline
    if workfut.finished():
      if not deadline.finished():
        deadline.cancelSoon()
      inc logos_p2p_successful_dials
    else:
      debug "Connection to remote peer timed out",
        timeout = node.connectTimeout, addrs = peerAddr.addrs
      inc logos_p2p_timeout_dials
      node.addSeen(peerAddr.peerId, SeenTableTimeTimeout)
      await cancelAndWait(workfut)
  except CancelledError as exc:
    if not deadline.finished():
      deadline.cancelSoon()
    await cancelAndWait(workfut)
    raise exc
  except LPError as exc:
    debug "Connection to remote peer failed", msg = exc.msg, addrs = peerAddr.addrs
    inc logos_p2p_failed_dials
    node.addSeen(peerAddr.peerId, SeenTableTimeDeadPeer)

proc connectWorker(node: LBP2PNode, index: int) {.async: (raises: [CancelledError]).} =
  debug "Connection worker started", index = index
  while true:
    # This loop will never produce HIGH CPU usage because it will wait
    # and block until it not obtains new peer from the queue ``connQueue``.
    let remotePeerAddr = await node.connQueue.popFirst()
    # Release outboundTable reservation for this id after we finish handling the
    # queue item (dial or skip), including on CancelledError from dialPeer.
    try:
      # Previous worker dial might have hit the maximum peers or peer became ineligible.
      if node.peerPool.len < node.hardMaxPeers and node.checkPeer(remotePeerAddr):
        node.outboundTable[remotePeerAddr.peerId] = OutboundConnStage.Dialing
        await node.dialPeer(remotePeerAddr, index)
    finally:
      node.outboundTable.del(remotePeerAddr.peerId)
      node.signalConnEvent(remotePeerAddr.peerId)

func minOutPeers*(wantedPeers: int): int =
  ## Minimum number of outbound peers required as defense against eclipse attacks.
  min(wantedPeers, max(wantedPeers div 10, 3))

proc handlePeer*(peer: Peer) {.async: (raises: [CancelledError]).} =
  let node = peer.network
  if peer.direction == PeerType.Incoming:
    let minOut = minOutPeers(node.wantedPeers)
    if node.peerPool.len >= node.hardMaxPeers or
        (node.peerPool.len >= node.wantedPeers and
         node.peerPool.lenCurrent({PeerType.Outgoing}) < minOut):
      debug "Rejecting incoming peer: pool at capacity and outbound peers below minimum",
        peer = peer,
        currentPeers = node.peerPool.len,
        wantedPeers = node.wantedPeers,
        outPeers = node.peerPool.lenCurrent({PeerType.Outgoing}),
        minOut = minOut
      await peer.disconnect(ClientShutDown)
      return

  let res = node.peerPool.addPeerNoWait(peer, peer.direction)
  case res:
  of PeerStatus.LowScoreError, PeerStatus.NoSpaceError:
    # Peer has low score or we do not have enough space in PeerPool,
    # we are going to disconnect it gracefully.
    # Peer' state will be updated in connection event.
    debug "Peer has low score or there no space in PeerPool",
          peer = peer, reason = res
    await peer.disconnect(FaultOrError)
  of PeerStatus.DeadPeerError:
    # Peer's lifetime future is finished, so its already dead,
    # we do not need to perform gracefull disconect.
    # Peer's state will be updated in connection event.
    discard
  of PeerStatus.DuplicateError:
    # Peer is already present in PeerPool, we can't perform disconnect,
    # because in such case we could kill both connections (connection
    # which is present in PeerPool and new one).
    # This is possible bug, because we could enter here only if number
    # of `peer.connections == 1`, it means that Peer's lifetime is not
    # tracked properly and we still not received `Disconnected` event.
    debug "Peer is already present in PeerPool", peer = peer
  of PeerStatus.Success:
    # Peer was added to PeerPool.
    peer.score = NewPeerScore
    peer.connectionState = ConnectionState.Connected
    debug "Peer successfully connected", peer = peer,
                                         connections = peer.connections

proc onConnEvent(
    node: LBP2PNode, peerId: PeerId, event: ConnEvent) {.
    async: (raises: [CancelledError]).} =
  let peer = node.getPeer(peerId)
  case event.kind
  of ConnEventKind.Connected:
    node.signalConnEvent(peerId)
    inc peer.connections
    debug "Peer connection upgraded", peer = $peerId,
                                      connections = peer.connections
    if peer.connections == 1:
      # Libp2p may connect multiple times to the same peer - using different
      # transports for both incoming and outgoing. For now, we'll count our
      # "fist" encounter with the peer as the true connection, leaving the
      # other connections be - libp2p limits the number of concurrent
      # connections to the same peer, and only one of these connections will be
      # active. Nonetheless, this quirk will cause a number of odd behaviours:
      # * For peer limits, we might miscount the incoming vs outgoing quota
      # * Protocol handshakes are wonky: we'll not necessarily use the newly
      #   connected transport - instead we'll just pick a random one!
      case peer.connectionState
      of ConnectionState.Disconnecting:
        # We got connection with peer which we currently disconnecting.
        # Normally this does not happen, but if a peer is being disconnected
        # while a concurrent (incoming for example) connection attempt happens,
        # we might end up here
        debug "Got connection attempt from peer that we are disconnecting",
             peer = peerId
        # ``switch.disconnect`` only raises ``CancelledError``, which propagates.
        await node.switch.disconnect(peerId)
        return
      of ConnectionState.None:
        # We have established a connection with the new peer.
        peer.connectionState = ConnectionState.Connecting
      of ConnectionState.Disconnected:
        # We have established a connection with the peer that we have seen
        # before - reusing the existing peer object is fine
        peer.connectionState = ConnectionState.Connecting
        peer.score = 0 # Will be set to NewPeerScore after handshake
      of ConnectionState.Connecting, ConnectionState.Connected:
        # This means that we got notification event from peer which we already
        # connected or connecting right now. If this situation will happened,
        # it means bug on `nim-libp2p` side.
        warn "Got connection attempt from peer which we already connected",
             peer = peerId
        await peer.disconnect(FaultOrError)
        return

      # Store connection direction inside Peer object.
      if event.incoming:
        peer.direction = PeerType.Incoming
      else:
        peer.direction = PeerType.Outgoing

      await peer.handlePeer()

  of ConnEventKind.Disconnected:
    dec peer.connections
    debug "Lost connection to peer", peer = peerId,
                                     connections = peer.connections

    if peer.connections == 0:
      debug "Peer disconnected", peer = $peerId, connections = peer.connections

      # Whatever caused disconnection, avoid connection spamming
      node.addSeen(peerId, SeenTableTimeReconnect)

      let fut = peer.disconnectedFut
      if not(isNil(fut)):
        fut.complete()
        peer.disconnectedFut = nil
      else:
        # TODO (cheatfate): This could be removed when bug will be fixed inside
        # `nim-libp2p`.
        debug "Got new event while peer is already disconnected",
              peer = peerId, peer_state = peer.connectionState
      peer.connectionState = ConnectionState.Disconnected

proc new(T: type LBP2PNode,
         config: NetworkConfig,
         switch: Switch, pubsub: GossipSub,
         announcedAddresses: openArray[MultiAddress],
         bootstrapPeers: openArray[PeerAddr],
         mountedProtocols = MountedProtocols(),
         rng: ref HmacDrbgContext): T =
  when not defined(local_testnet):
    let connectTimeout = chronos.minutes(1)
  else:
    let connectTimeout = chronos.seconds(10)

  let node = T(
    switch: switch,
    pubsub: pubsub,
    wantedPeers: config.maxPeers,
    hardMaxPeers: config.hardMaxPeers.get(config.maxPeers * 3 div 2), #*1.5
    peerPool: newPeerPool[Peer, PeerId](),
    # Its important here to create AsyncQueue with limited size, otherwise
    # it could produce HIGH cpu usage.
    connQueue: newAsyncQueue[PeerAddr](ConcurrentConnections),
    mountedProtocols: mountedProtocols,
    rng: rng,
    connectTimeout: connectTimeout,
    announcedAddresses: @announcedAddresses,
    bootstrapPeers: @bootstrapPeers,
    bootstrapTimeout:
      if config.bootstrapTimeout > 0:
        config.bootstrapTimeout.seconds
      else:
        DefaultBootstrapTimeout.seconds,
    peerChangeEvent: newAsyncEvent(),
  )

  proc peerHook(
      peerId: PeerId,
      event: ConnEvent
  ): Future[void] {.async: (raises: [CancelledError], raw: true), gcsafe.} =
    onConnEvent(node, peerId, event)

  switch.addConnEventHandler(peerHook, ConnEventKind.Connected)
  switch.addConnEventHandler(peerHook, ConnEventKind.Disconnected)

  proc scoreCheck(peer: Peer): bool =
    peer.score >= PeerScoreLowLimit

  proc onDeletePeer(peer: Peer) =
    peer.releasePeer()

  node.peerPool.setScoreCheck(scoreCheck)
  node.peerPool.setOnDeletePeer(onDeletePeer)

  node

proc startListening*(node: LBP2PNode) {.async.} =
  try:
    await node.switch.start()
  except LPError as exc:
    fatal "Failed to start LibP2P transport. Listen address/port may be already in use",
          exc = exc.msg
    quit 1

  let fullAddrs = node.switch.peerInfo.fullAddrs().valueOr:
    warn "LibP2P transport started, but couldn't compute fullAddrs()",
      error
    @[]
  if fullAddrs.len > 0:
    notice "LibP2P transport started", fullAddrs = fullAddrs

  if node.announcedAddresses.len > 0:
    notice "Configured advertised addresses",
      announcedAddresses = node.announcedAddresses
  else:
    debug "No advertised addresses configured"

proc peerTrimmerHeartbeat(node: LBP2PNode) {.async: (raises: [CancelledError]).} =
  # Disconnect peers in excess of the (soft) max peer count (lowest scoring first),
  # protecting minOutPeers outbound connections to defend against eclipse attacks.
  while true:
    var connectedPeers = 0
    var connectedOutPeers = 0
    var lowestConnectedPeer: Peer = nil
    var lowestInboundPeer: Peer = nil

    for peer in node.peerPool.peers(order = SortOrder.Ascending):
      if peer.connectionState == ConnectionState.Connected:
        inc connectedPeers
        if lowestConnectedPeer == nil:
          lowestConnectedPeer = peer
        if peer.direction == PeerType.Outgoing:
          inc connectedOutPeers
        elif lowestInboundPeer == nil:
          lowestInboundPeer = peer

    let excessPeers = connectedPeers - node.wantedPeers
    let minOut = minOutPeers(node.wantedPeers)

    if excessPeers > 0:
      let candidate =
        if connectedOutPeers <= minOut and lowestInboundPeer != nil:
          lowestInboundPeer
        else:
          lowestConnectedPeer

      if candidate != nil:
        debug "Trimming excess lowest-scoring peer", peer = candidate.peerId
        await candidate.disconnect(ClientShutDown)

    await sleepAsync(1.seconds div max(1, excessPeers))

template shouldDisconnectBootstrap*(
    peerPoolLen, wantedPeers, bootstrapPeersInPool: int
): bool =
  ## True when the node is at/above its peer target and at least one admitted
  ## peer is not a configured bootstrap peer (so bootstrap links may be released).
  ##
  ## Benchmark (20M ops): template (8.68 ms) vs inline (10.55 ms) vs default (10.98 ms).
  ##
  ## Matches bootstrap link maintenance in the P2P Network Specification:
  ## https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/draft/p2p-network.md
  ## https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/p2p-network-bootstrapping.md
  peerPoolLen >= wantedPeers and (peerPoolLen - bootstrapPeersInPool) > 0

proc runBootstrapLinkMaintenanceTick*(
    node: LBP2PNode
) {.async: (raises: [CancelledError]).} =
  ## One evaluation of bootstrap link maintenance: disconnect configured bootstrap
  ## peers when ``shouldDisconnectBootstrap`` holds. Used by
  ## ``bootstrapHeartbeat`` and tests (no fixed sleep). Policy matches the P2P Network
  ## Specification (see doc comment on ``shouldDisconnectBootstrap``):
  ## https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/draft/p2p-network.md
  ## https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/p2p-network-bootstrapping.md
  if node.bootstrapPeers.len == 0:
    return

  let connectedBootstrapPeers =
    node.bootstrapPeers.filterIt(
      node.peerPool.hasPeer(it.peerId)
    ).mapIt(it.peerId)

  if not shouldDisconnectBootstrap(
      node.peerPool.len, node.wantedPeers, connectedBootstrapPeers.len):
    return

  # Disconnect one bootstrap peer at a time for gradual release
  if connectedBootstrapPeers.len > 0:
    let peerIdToDrop =
      if not isNil(node.switch.rng):
        node.switch.rng.pickOne(connectedBootstrapPeers).get(connectedBootstrapPeers[0])
      else:
        connectedBootstrapPeers[0]
    let peer = node.getPeer(peerIdToDrop)
    await peer.disconnect(ClientShutDown)

proc bootstrapHeartbeat(node: LBP2PNode) {.async: (raises: [CancelledError]).} =
  if node.bootstrapPeers.len == 0:
    return

  while true:
    # Sleep first so onboarding and discovery can settle before evaluating release.
    await sleepAsync(KadBootstrapHeartbeatPeriod)
    if node.peerPool.len == 0:
      discard await node.enqueueBootstrapPeers()
    else:
      await runBootstrapLinkMaintenanceTick(node)

proc runKadDiscoveryLookupLoop(node: LBP2PNode) {.async: (raises: [CancelledError]).} =
  debug "Starting Kad discovery lookup loop"
  while true:
    if node.peerPool.len < node.wantedPeers or
        node.peerPool.lenCurrent({PeerType.Outgoing}) < minOutPeers(node.wantedPeers):
      await node.mountedProtocols.kad.kadDiscoveryLookupWalk(node.switch.rng)

    await sleepAsync(KadDiscoveryLookupPeriod)

proc runKadDiscoveryEnqueueLoop(node: LBP2PNode) {.async: (raises: [CancelledError]).} =
  debug "Starting Kad discovery enqueue loop"
  while true:
    if node.peerPool.len < node.wantedPeers or
        node.peerPool.lenCurrent({PeerType.Outgoing}) < minOutPeers(node.wantedPeers):
      let kad = node.mountedProtocols.kad
      let (discoveredCount, queuedCount) =
        await enqueueKadDiscoveredPeers(
          kad,
          node.switch,
          node.peerPool,
          proc(discovered: DiscoveredPeerAddr): Future[bool]
              {.async: (raises: [CancelledError]), gcsafe.} =
            await node.enqueueOutboundPeer(
              PeerAddr(peerId: discovered.peerId, addrs: discovered.addrs))
        )
      debug "Kad discovery enqueue tick",
        wanted_peers = node.wantedPeers,
        current_peers = len(node.peerPool),
        current_out_peers = node.peerPool.lenCurrent({PeerType.Outgoing}),
        min_out_peers = minOutPeers(node.wantedPeers),
        discovered_nodes = discoveredCount,
        new_peers = queuedCount
      if queuedCount == 0:
        let currentPeers = len(node.peerPool)
        if currentPeers <= node.wantedPeers shr 2: # 25%
          warn "Peer count low, no new Kad peers discovered",
            discovered_nodes = discoveredCount, new_peers = queuedCount,
            current_peers = currentPeers, wanted_peers = node.wantedPeers

    await sleepAsync(KadDiscoveryLoopPeriod)

func bootstrapPeerIds*(node: LBP2PNode): seq[PeerId] =
  node.bootstrapPeers.mapIt(it.peerId)

proc connectedBootstrapPeerIds*(node: LBP2PNode): seq[PeerId] =
  ## Returns the PeerIds of all configured bootstrap peers currently admitted
  ## to the peer pool.
  var res = newSeqOfCap[PeerId](node.bootstrapPeers.len)
  for b in node.bootstrapPeers:
    if node.peerPool.hasPeer(b.peerId):
      res.add(b.peerId)
  res

proc waitForBootstrapPeers*(
    node: LBP2PNode,
): Future[seq[PeerId]] {.async: (raises: [CancelledError]).} =
  ## Wait until at least one configured bootstrap peer connects, or upon
  ## full bootstrapTimeout expiration.
  if node.bootstrapPeers.len == 0:
    return @[]

  let totalConfigured = node.bootstrapPeers.len
  let deadline = Moment.now() + node.bootstrapTimeout
  var lastLogTime = Moment.now()

  info "Waiting to establish connection with bootstrap peers",
    configured = totalConfigured,
    timeout = node.bootstrapTimeout

  while true:
    node.peerChangeEvent.clear()
    let readyPeers = node.connectedBootstrapPeerIds()

    # Return once at least 1 bootstrap peer is connected
    if readyPeers.len > 0:
      info "Bootstrap peer readiness established",
        connected = readyPeers.len,
        configured = totalConfigured
      return readyPeers

    let now = Moment.now()
    let remaining = deadline - now

    # Timeout reached with no peers connected
    if remaining <= ZeroDuration:
      debug "Bootstrap connection timeout reached with no peers connected",
        configured = totalConfigured,
        timeout = node.bootstrapTimeout
      return @[]

    if now - lastLogTime >= 5.seconds:
      lastLogTime = now
      info "Still trying to connect to bootstrap peers...",
        connected = 0,
        configured = totalConfigured,
        remainingTimeout = remaining

    let waitInterval = min(remaining, 5.seconds)
    discard await withTimeout(node.peerChangeEvent.wait(), waitInterval)

proc start*(node: LBP2PNode) {.async: (raises: [CancelledError]).} =
  proc onPeerCountChanged() =
    trace "Number of peers has been changed", length = len(node.peerPool)
    logos_p2p_peers.set int64(len(node.peerPool))
    if not node.peerChangeEvent.isSet():
      node.peerChangeEvent.fire()

  node.peerPool.setPeerCounter(onPeerCountChanged)

  for i in 0 ..< ConcurrentConnections:
    node.backgroundTasks.add connectWorker(node, i)

  let kadBootstrapInfos = node.bootstrapPeers.mapIt(
    PeerInfo(peerId: it.peerId, addrs: it.addrs)
  )
  if not isNil(node.mountedProtocols.kad):
    if kadBootstrapInfos.len > 0:
      notice "Starting Kad DHT with bootstrap peers",
        bootstrapPeers = kadBootstrapInfos.len
      debug "Bootstrapping Kad DHT instance"
      await kadBootstrap(
        node.mountedProtocols.kad, kadBootstrapInfos,
        proc(b: PeerInfo): Future[bool].Raising([CancelledError]) =
          connectViaConnQueue(
            node,
            PeerAddr(peerId: b.peerId, addrs: b.addrs),
            proc(p: PeerAddr): bool {.gcsafe, raises: [].} =
              node.checkPeer(p),
            node.connectTimeout + (node.connectTimeout div 2)))
    else:
      notice "Starting Kad DHT without bootstrap peers " &
        "(routing table may fill from inbound traffic only)"

  if node.bootstrapPeers.len == 0:
    notice "No libp2p bootstrap multiaddrs configured"

  if not isNil(node.mountedProtocols.kad):
    debug "Starting Kad discovery loops (lookup + enqueue)"
    let lookupFut = node.runKadDiscoveryLookupLoop()
    let enqueueFut = node.runKadDiscoveryEnqueueLoop()
    traceAsyncErrors lookupFut
    traceAsyncErrors enqueueFut
    node.backgroundTasks.add lookupFut
    node.backgroundTasks.add enqueueFut

  node.backgroundTasks.add node.peerTrimmerHeartbeat()
  node.backgroundTasks.add node.bootstrapHeartbeat()

proc stop*(node: LBP2PNode) {.async: (raises: [CancelledError]).} =
  var waitedFutures: seq[FutureBase] = @[]
  if not isNil(node.mountedProtocols.kad):
    waitedFutures.add FutureBase(node.mountedProtocols.kad.stop())
  if not isNil(node.pubsub):
    waitedFutures.add FutureBase(node.pubsub.stop())
  waitedFutures.add FutureBase(node.switch.stop())
  for fut in node.backgroundTasks:
    if not isNil(fut) and not fut.finished():
      waitedFutures.add FutureBase(fut.cancelAndWait())
  node.backgroundTasks.setLen(0)

  for pid, event in node.connEvents:
    event.fire()
  node.connEvents.clear()

  let
    timeout = 5.seconds
    completed = await withTimeout(allFutures(waitedFutures), timeout)
  if not completed:
    trace "LBP2PNode.stop(): timeout reached", timeout = timeout,
      futureErrors = waitedFutures.filterIt(not isNil(it.error)).mapIt(
        it.error.msg)


template udpEndpoint(address, port): auto =
  MultiAddress.init(address, udpProtocol, port)

## Specs mandate QUIC (`quic-v1`) as the Logos Chain libp2p transport baseline:
## https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/draft/p2p-network.md#transport
##
## Build a QUIC listener/dialable multiaddr endpoint:
## ``/ip4|ip6/<addr>/udp/<port>/quic-v1``
##
## Returns ``Result`` because constructing ``"/quic-v1"`` can raise ``MaError``
## depending on multiaddr parsing / codec table.
func quicEndPoint(address: IpAddress, port: Port): Result[MultiAddress, string] =
  try:
    ok(
      udpEndpoint(address, port) &
        MultiAddress.init("/quic-v1").get()
    )
  except MaError as exc:
    err(exc.msg)

proc loadBootstrapPeers(config: NetworkConfig): seq[PeerAddr] =
  var peers: seq[PeerAddr]
  for (peerId, maddr) in loadBootstrapNodes(config):
    peers.add(PeerAddr(peerId: peerId, addrs: @[maddr]))
  peers

func initNetKeys(privKey: PrivateKey): NetKeyPair =
  let pubKey = privKey.getPublicKey().expect("working public key from random")
  NetKeyPair(seckey: privKey, pubkey: pubKey)

proc getRandomNetKeys*(rng: ref HmacDrbgContext): NetKeyPair =
  let privKey = PrivateKey.random(Ed25519, newBearSslRng(rng)).valueOr:
    fatal "Could not generate random network key file"
    quit QuitFailure
  initNetKeys(privKey)

import nimcrypto/sha2

func gossipId(data: openArray[byte], topic: string): seq[byte] =
  var ctx {.noinit.}: sha2.sha256
  ctx.init()
  ctx.update(data)
  ctx.finish().data[0..19]

proc newSwitch(
    config: NetworkConfig,
    seckey: PrivateKey,
    address: MultiAddress,
    rng: ref HmacDrbgContext,
): Result[Switch, string] =
  var sb = SwitchBuilder.new()
  try:
    ok sb
    .withPrivateKey(seckey)
    .withAddress(address)
    .withWildcardResolver()
    .withIdentifyPusher(false)
    .withRng(newBearSslRng(rng))
    .withNoise()
    .withMaxConnections(config.maxPeers)
    .withAgentVersion(config.agentString)
    .withQuicTransport()
    # AutoNAT v2 dial-back opens a transient second session to a peer we may
    # already be connected to (the bootstrap link). The default per-peer cap
    # rejects that session over QUIC, so allow headroom for the dial-back.
    .withMaxConnsPerPeer(2)
    .withAutonatV2Server(
      AutonatV2Config.new(allowPrivateAddresses = config.autonatAllowPrivateAddresses)
    )
    # Do not probe on PeerEventKind.Joined: bootstrap dials complete before the
    # peer-pool handshake finishes, and concurrent dial-back attempts fail (QUIC
    # EDialError).
    .withNAT(autonatConfig(AutonatV2, v2ServiceConfig =
      Opt.some(AutonatV2ServiceConfig.new(askNewConnectedPeers = false))))
    .build()
  except LPError as exc:
    err(exc.msg)

proc createLBP2PNode*(
    rng: ref HmacDrbgContext,
    config: NetworkConfig,
    netKeys: NetKeyPair,
): Result[LBP2PNode, string] =
  let
    quicPort = config.quicPort

    listenAddress =
      config.listenAddress.get(getAutoAddress(Port(0)).toIpAddress())

    quicPorts = @[(port: quicPort, protocol: PortProtocol.UDP)]
    (extIp, extPorts) =
      setupAddress(config.nat, listenAddress, quicPorts, clientId)
    extQuicPort =
      if extPorts.len > 0 and extPorts[0].isSome:
        Opt.some(extPorts[0].value.port)
      else:
        Opt.none(Port)

    hostAddress =
      ?quicEndPoint(listenAddress, quicPort)
    announcedAddresses =
      if extIp.isSome and extQuicPort.isSome:
        @[
          ?quicEndPoint(extIp.value, extQuicPort.value)
        ]
      else:
        @[]

  debug "Initializing networking", hostAddress,
                                   network_public_key = netKeys.pubkey,
                                   announcedAddresses

  # TODO nim-libp2p still doesn't have support for announcing addresses
  # that are different from the host address (this is relevant when we
  # are running behind a NAT).
  let switch = ?newSwitch(config, netKeys.seckey, hostAddress, rng)
  let ident =
    try:
      mountIdentifyProtocol(switch, switch.peerInfo, config.logosNetwork)
    except LPError as exc:
      return err("Cannot mount Logos Identify protocols: " & exc.msg)
  let addressPolicy =
    if config.autonatAllowPrivateAddresses:
      noPrivateAddressPolicy
    else:
      publicRoutableAddressPolicy

  let kad =
    try:
      mountKadProtocol(switch, config.logosNetwork, switch.rng, addressPolicy)
    except LPError as exc:
      return err("Cannot mount Logos Kad protocols: " & exc.msg)
  let mounted = MountedProtocols(kad: kad, identify: ident)

  func msgIdProvider(m: messages.Message): Result[seq[byte], ValidationResult] =
    ok(gossipId(m.data, m.topic))

  let
    bootstrapPeers = loadBootstrapPeers(config)
    params = GossipSubParams.init(
      pruneBackoff = chronos.minutes(1),
      unsubscribeBackoff = chronos.seconds(10),
      floodPublish = true,
      gossipFactor = 0.05,
      d = 8,
      dLow = 6,
      dHigh = 12,
      dScore = 6,
      dOut = 6 div 2, # less than dlow and no more than dlow/2
      dLazy = 6,
      heartbeatInterval = chronos.milliseconds(700),
      historyLength = 6,
      historyGossip = 3,
      fanoutTTL = chronos.seconds(60),
      gossipThreshold = -4000,
      publishThreshold = -8000,
      graylistThreshold = -16000, # also disconnect threshold
      opportunisticGraftThreshold = 0,
      decayInterval = chronos.seconds(12),
      decayToZero = 0.01,
      retainScore = chronos.seconds(385),
      appSpecificWeight = 0.0,
      ipColocationFactorWeight = -53.75,
      ipColocationFactorThreshold = 3.0,
      behaviourPenaltyWeight = -15.9,
      behaviourPenaltyDecay = 0.986,
      disconnectBadPeers = true
    )
    pubsub =
      try:
        GossipSub.init(
          switch = switch,
          msgIdProvider = msgIdProvider,
          # We process messages in the validator, so we don't need data callbacks
          triggerSelf = false,
          sign = false,
          verifySignature = false,
          anonymize = true,
          maxMessageSize = static(MAX_PAYLOAD_SIZE.int),
          rng = switch.rng,
          parameters = params,
        )
      except InitializationError as exc:
        raiseAssert "Invalid gossipsub parameters: " & exc.msg

  try:
    switch.mount(pubsub)
  except LPError as exc: # Invalid params..
    return err("Cannot mount pubsub: " & exc.msg)

  let node = LBP2PNode.new(
    config, switch, pubsub, announcedAddresses, bootstrapPeers,
    mountedProtocols = mounted,
    rng = rng,
  )

  if bootstrapPeers.len > 0:
    notice "Loaded libp2p bootstrap multiaddrs", count = bootstrapPeers.len
  else:
    notice "No libp2p bootstrap multiaddrs loaded"

  node.pubsub.subscriptionValidator =
    proc(topic: string): bool {.gcsafe.} =
      topic in node.validTopics

  ok node

proc subscribe*(
    node: LBP2PNode, topic: string, topicParams: TopicParams,
    enableTopicMetrics: bool = false) =
  if enableTopicMetrics:
    node.pubsub.knownTopics.incl(topic)

  node.pubsub.topicParams[topic] = topicParams

  # Passing in `nil` because we do all message processing in the validator
  node.pubsub.subscribe(topic, nil)

proc newValidationResultFuture(v: ValidationResult): Future[ValidationResult]
    {.async: (raises: [CancelledError], raw: true).} =
  let res = newFuture[ValidationResult]("network.execValidator")
  res.complete(v)
  res

func addValidator*[MsgType](
    node: LBP2PNode,
    topic: string,
    msgValidator: ValidationSyncProc[MsgType]
) =
  # Message validators run when subscriptions are enabled - they validate the
  # data and return an indication of whether the message should be broadcast
  # or not - validation is `async` but implemented without the macro because
  # this is a performance hotspot.
  proc execValidator(topic: string, message: GossipMsg):
      Future[ValidationResult] =
    inc logos_p2p_gossip_messages_received
    trace "Validating incoming gossip message", len = message.data.len, topic

    let res = if message.data.len > 0:
      try:
        msgValidator(Bincode.decode(message.data, MsgType), message.fromPeer) # doesn't raise!
      except SerializationError as e:
        debug "Error decoding gossip",
          topic, len = message.data.len, error = e.msg
        ValidationResult.Reject
    else:
      debug "Error decoding gossip", topic, len = message.data.len
      ValidationResult.Reject

    newValidationResultFuture(res)

  node.validTopics.incl topic # Only allow subscription to validated topics
  node.pubsub.addValidator(topic, execValidator)

proc addAsyncValidator*[MsgType](
    node: LBP2PNode,
    topic: string,
    msgValidator: ValidationAsyncProc[MsgType]
) =
  proc execValidator(
      topic: string,
      message: GossipMsg
  ): Future[ValidationResult] {.async: (raw: true).} =
    inc logos_p2p_gossip_messages_received
    trace "Validating incoming gossip message", len = message.data.len, topic

    if message.data.len > 0:
      try:
        msgValidator(Bincode.decode(message.data, MsgType), message.fromPeer) # doesn't raise!
      except SerializationError as e:
        debug "Error decoding gossip",
          topic, len = message.data.len, error = e.msg
        newValidationResultFuture(ValidationResult.Reject)
    else:
      debug "Error decoding gossip", topic, len = message.data.len
      newValidationResultFuture(ValidationResult.Reject)

  node.validTopics.incl topic # Only allow subscription to validated topics

  node.pubsub.addValidator(topic, execValidator)

when defined(unittest) or defined(test):
  func outboundConnQueueLen*(node: LBP2PNode): int {.inline.} =
    node.connQueue.len

  proc seenTableContains*(node: LBP2PNode, pid: PeerId): bool {.inline.} =
    node.isSeen(pid)

  proc setConnectTimeout*(node: LBP2PNode, timeout: chronos.Duration) {.inline.} =
    node.connectTimeout = timeout

  proc setDirection*(peer: Peer, direction: PeerType) {.inline.} =
    peer.direction = direction

{.pop.}
