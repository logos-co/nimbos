# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[algorithm, sequtils, strutils],
  chronos,
  chronos/unittest2/asynctests,
  libp2p/[multiaddress, peerid, peerstore, switch, wire],
  libp2p/protocols/kademlia,
  presto/[route, server],
  ./helpers,
  ./testutil,
  ../logos_chain/api/[handlers, paths],
  ../logos_chain/chain/genesis,
  ../logos_chain/conf,
  ../logos_chain/core/[local_tree, types],
  ../logos_chain/networking/network

from ../logos_chain/binary_common import validateBeaconApiQueries

suite "Logos REST node API stub endpoints":
  var
    server: RestServerRef
    address: TransportAddress

  block:
    let serverAddress = initTAddress("127.0.0.1:0")
    var router = RestRouter.init(validateBeaconApiQueries)
    router.installNodeApiHandlers(nil) # LBNode is nil for stubs

    let sres = RestServerRef.new(router, serverAddress)
    server = sres.get()
    server.start()
    address = server.localAddress()

  asyncTest "GET /cryptarchia/headers returns empty list":
    let res = await httpClient(address, MethodGet, CRYPTARCHIA_HEADERS, "")
    check res.status == 200
    check res.data == "[]"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /cryptarchia/lib-stream returns empty body":
    let res = await httpClient(address, MethodGet, CRYPTARCHIA_LIB_STREAM, "")
    check res.status == 200
    check res.data.len == 0
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /cryptarchia/info returns 503 without a node":
    let res = await httpClient(address, MethodGet, CRYPTARCHIA_INFO_PATH, "")
    check res.status == 503
    check res.data ==
      "{\"code\":503,\"message\":\"" & ChainNotReadyError & "\"}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /leader/claim returns empty object":
    let res = await httpClient(address, MethodPost, LEADER_CLAIM_PATH, "")
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /mantle/metrics returns empty object":
    let res = await httpClient(address, MethodGet, MANTLE_METRICS, "")
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /mantle/status returns empty list":
    let res =
      await httpClient(address, MethodPost, MANTLE_STATUS, "{}", "application/json")
    check res.status == 200
    check res.data == "[]"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /mempool/add/tx returns empty body":
    let res =
      await httpClient(address, MethodPost, MEMPOOL_ADD_TX, "{}", "application/json")
    check res.status == 200
    check res.data.len == 0
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /network/info returns 503 without a node":
    let res = await httpClient(address, MethodGet, NETWORK_INFO, "")
    check res.status == 503
    check res.data ==
      "{\"code\":503,\"message\":\"" & NetworkNotReadyError & "\"}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /sdp/activity returns empty list":
    let res =
      await httpClient(address, MethodPost, SDP_POST_ACTIVITY, "{}", "application/json")
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /sdp/declaration returns wrapped empty string":
    let res = await httpClient(
      address, MethodPost, SDP_POST_DECLARATION, "{}", "application/json"
    )
    check res.status == 200
    check res.data == """{"data":""}"""
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /sdp/withdrawal returns empty object":
    let res = await httpClient(
      address, MethodPost, SDP_POST_WITHDRAWAL, "{}", "application/json"
    )
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /storage/block returns empty quoted string":
    let res =
      await httpClient(address, MethodPost, STORAGE_BLOCK, "{}", "application/json")
    check res.status == 200
    check res.data == "\"\""
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /test/membership/update returns empty object":
    let res = await httpClient(address, MethodPost, UPDATE_MEMBERSHIP, "")
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /wallet/{public_key}/balance returns empty object":
    let dummyKey = "0".repeat(64)
    let walletPath = WALLET_BALANCE_PATH.replace("{public_key}", dummyKey)
    let res = await httpClient(address, MethodGet, walletPath, "")
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /wallet/{public_key}/balance rejects invalid public_key":
    let badKey = "not-hex"
    let walletPath = WALLET_BALANCE_PATH.replace("{public_key}", badKey)
    let res = await httpClient(address, MethodGet, walletPath, "")
    check res.status == 404

  asyncTest "validateBeaconApiQueries accepts valid wallet public_key with and without 0x":
    let key = "0".repeat(64)
    check validateBeaconApiQueries("{public_key}", key) == 0
    check validateBeaconApiQueries("{public_key}", "0x" & key) == 0

  asyncTest "validateBeaconApiQueries rejects invalid wallet public_key lengths and characters":
    check validateBeaconApiQueries("{public_key}", "0".repeat(63)) == 1
    check validateBeaconApiQueries("{public_key}", "0".repeat(65)) == 1
    check validateBeaconApiQueries("{public_key}", "g".repeat(64)) == 1

  asyncTest "POST /wallet/transactions/transfer-funds returns empty object":
    let res = await httpClient(
      address, MethodPost, WALLET_TRANSACTIONS_TRANSFER_FUNDS_PATH, "{}",
      "application/json",
    )
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /cryptarchia/blocks returns empty list":
    let res = await httpClient(address, MethodGet, BLOCKS, "")
    check res.status == 200
    check res.data == "[]"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /cryptarchia/events/blocks/stream returns empty body":
    let res = await httpClient(address, MethodGet, BLOCKS_STREAM, "")
    check res.status == 200
    check res.data.len == 0
    check res.headers.getString("content-type") == "application/json"

  test "teardown rest server":
    {.gcsafe.}:
      waitFor server.stop()
      waitFor server.closeWait()

suite "Logos REST /cryptarchia/info":
  test "genesis-only tree reports genesis as tip and LIB":
    let
      genesis = createGenesisBlock(minimalSignedTx()).get
      gid = blockId(genesis.header)
      info = cryptarchiaInfo(newLocalTree(genesis, 1'u64))
    check Hash32(info.cryptarchia_info.tip) == gid
    check Hash32(info.cryptarchia_info.lib) == gid
    check uint64(info.cryptarchia_info.height) == 0
    check uint64(info.cryptarchia_info.slot) == genesis.header.slot
    check uint64(info.cryptarchia_info.lib_slot) == genesis.header.slot
    check info.cryptarchia_info.state == RestConsensusState.Online
    check info.phase == RestChainPhase.Following

  test "LIB stays at genesis after one block":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm).get
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = childBlock(genesis.header, gid, 1'u64, [sm])
      id1 = blockId(b1.header)
    check tree.addBlockToTree(b1)
    tree.tryUpdateLib()
    let info = cryptarchiaInfo(tree)
    check Hash32(info.cryptarchia_info.tip) == id1
    check uint64(info.cryptarchia_info.height) == 1
    check Hash32(info.cryptarchia_info.lib) == gid

  test "LIB moves to block 1 after two blocks":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm).get
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = childBlock(genesis.header, gid, 1'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, 2'u64, [sm])
      id2 = blockId(b2.header)
    check tree.addBlockToTree(b1)
    tree.tryUpdateLib()
    check tree.addBlockToTree(b2)
    tree.tryUpdateLib()
    let info = cryptarchiaInfo(tree)
    check Hash32(info.cryptarchia_info.tip) == id2
    check uint64(info.cryptarchia_info.height) == 2
    check Hash32(info.cryptarchia_info.lib) == id1
    check uint64(info.cryptarchia_info.lib_slot) == b1.header.slot

  test "JSON has bare numbers, plain hex ids, and no data envelope":
    var lib, tip: Hash32
    lib.fill(0x01'u8)
    tip.fill(0xab'u8)
    let info = RestChainServiceInfo(
      cryptarchia_info: RestCryptarchiaInfo(
        lib: RestHeaderId(lib),
        lib_slot: RestU64(7),
        tip: RestHeaderId(tip),
        slot: RestU64(9),
        height: RestU64(3),
        state: RestConsensusState.Online,
      ),
      phase: RestChainPhase.Following,
    )
    check RestJson.encode(info) ==
      "{\"cryptarchia_info\":{\"lib\":\"" & "01".repeat(32) &
      "\",\"lib_slot\":7,\"tip\":\"" & "ab".repeat(32) &
      "\",\"slot\":9,\"height\":3,\"state\":\"Online\"}," &
      "\"phase\":\"Following\"}"

suite "Logos REST /network/info":
  asyncTest "one started node reports its id, bound addresses, and zero counts":
    let node = await startTestNode("network-info-single")
    try:
      let info = networkInfo(node)
      check info.peer_id == node.peerId
      check info.listen_addresses.len > 0
      check info.listen_addresses.allIt(initTAddress(it).get().port != Port(0))
      check info.connected_peers.len == 0
      check uint64(info.n_peers) == 0
      check uint64(info.n_connections) == 0
      check uint64(info.n_pending_connections) == 0
      check info.discovered_peers.len == 0
      check uint64(info.n_discovered_peers) == 0
    finally:
      await node.stop()

  asyncTest "listenAddresses keeps a loopback bind as is":
    let node = await startTestNode("network-info-loopback")
    try:
      let addrs = node.listenAddresses()
      check addrs.len == 1
      check addrs == node.switch.peerInfo.listenAddrs
      check addrs[0].getIp() == Opt.some(TestLoopbackIp)
      check initTAddress(addrs[0]).get().port != Port(0)
    finally:
      await node.stop()

  asyncTest "listenAddresses expands a wildcard bind":
    let
      conf = NetworkConfig(
        listenAddress: some(parseIpAddress("0.0.0.0")),
        quicPort: TestQuicAnyPort,
        maxPeers: 16,
        hardMaxPeers: some(16),
        agentString: "network-info-wildcard",
        autonatAllowPrivateAddresses: true,
        bootstrapTimeout: DefaultBootstrapTimeout,
        logosNetwork: LogosNetworkKind.Testnet,
      )
      node = createLBP2PNode(getTestHmacRng(), conf, getRandomNetKeys()).get()
    try:
      await node.startListening()
      let addresses = node.listenAddresses().mapIt(initTAddress(it).get())
      check addresses.len > 0
      check addresses.allIt(not it.isAnyLocal() and it.port != Port(0))
      check addresses.allIt(it.family == AddressFamily.IPv4)
    finally:
      await node.stop()

  asyncTest "two connected nodes report one established peer":
    let peers = await createBootstrapPeers()
    try:
      await peers.dialer.start()
      check waitUntil(uint64(networkInfo(peers.dialer).n_peers) == 1)
      let info = networkInfo(peers.dialer)
      check info.connected_peers == @[peers.listenerPeerId]
      check uint64(info.n_connections) >= 1
    finally:
      await peers.dialer.stop()
      await peers.listener.stop()

  test "JSON has string ids and addresses, bare counts, and no data envelope":
    let
      localId = getRandomPeerId()
      remoteId = getRandomPeerId()
      info = RestNetworkInfo(
        listen_addresses:
          @[MultiAddress.init("/ip4/127.0.0.1/udp/3000/quic-v1").get()],
        peer_id: localId,
        connected_peers: @[remoteId],
        n_peers: RestU64(1),
        n_connections: RestU64(2),
        n_pending_connections: RestU64(0),
        discovered_peers: @[remoteId],
        n_discovered_peers: RestU64(1),
      )
    check RestJson.encode(info) ==
      "{\"listen_addresses\":[\"/ip4/127.0.0.1/udp/3000/quic-v1\"]," &
      "\"peer_id\":\"" & $localId & "\"," &
      "\"connected_peers\":[\"" & $remoteId & "\"]," &
      "\"n_peers\":1,\"n_connections\":2,\"n_pending_connections\":0," &
      "\"discovered_peers\":[\"" & $remoteId & "\"]," &
      "\"n_discovered_peers\":1}"

  asyncTest "discoveredPeers includes a pool peer that the enqueue path skips":
    let node = await startTestNode("network-info-discovered")
    try:
      let
        kad = node.mountedProtocols.kad
        remotePeerId = getRandomPeerId()
        remotePeer = node.getPeer(remotePeerId)
      check kad.rtable.insert(remotePeerId)
      node.switch.peerStore[AddressBook].extend(
        remotePeerId,
        @[MultiAddress.init("/ip4/127.0.0.1/udp/4333/quic-v1").get()])
      remotePeer.setDirection(PeerType.Outgoing)
      check node.peerPool.addPeerNoWait(remotePeer, PeerType.Outgoing) ==
        PeerStatus.Success

      check discoveredPeers(kad, node.switch) == @[remotePeerId]

      var enqueueCalls = 0
      proc enqueueAll(p: DiscoveredPeerAddr): Future[bool] {.
          async: (raises: [CancelledError]).} =
        inc enqueueCalls
        return true
      let (discovered, queued) = await enqueueKadDiscoveredPeers(
        kad, node.switch, node.peerPool, enqueueAll)
      check discovered == 0
      check queued == 0
      check enqueueCalls == 0
    finally:
      await node.stop()

  asyncTest "pendingDialCount does not count queued entries":
    let
      node = createTestNode("network-info-pending")
      pid = getRandomPeerId()
    try:
      check await tryEnqueueOutboundConn(
        node,
        PeerAddr(
          peerId: pid,
          addrs: @[MultiAddress.init("/ip4/127.0.0.1/udp/4334/quic-v1").get()]),
        alwaysAllowPeer)
      check node.outboundStage(pid) == Opt.some(OutboundConnStage.Queued)
      check node.pendingDialCount() == 0
    finally:
      await node.stop()

{.pop.}
