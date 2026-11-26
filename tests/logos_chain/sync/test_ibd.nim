# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  chronos/unittest2/asynctests,
  libp2p/switch,
  ../../../logos_chain/networking/network,
  ../../../logos_chain/core/types,
  ../../../logos_chain/chain/[chain, local_tree],
  ../../../logos_chain/sync/[framing, types, sync_client, sync_server, syncer],
  ./helpers,
  ../../testutil

template peerProvider(peers: varargs[PeerId]): PeerProvider =
  (proc(): seq[PeerId] = @peers)

proc mountStalledServer(
    sw: Switch, gate: Future[void].Raising([CancelledError])
) {.raises: [LPError].} =
  let lp = LPProtocol.new(
    codecs = @[testChainSyncProtocol],
    handler = proc(conn: Connection, proto: string) {.async: (raises: [CancelledError]).} =
      await gate
  )
  lp.started = true
  sw.mount(lp)

suite "sync/initial_block_download (download blocks)":
  test "decodeSyncBlock roundtrip (genesis block on sync wire)":
    let
      genesis = testGenesisBlock()
      genesisWire = try:
        encode(genesis, cryptarchiaSyncBincodeConfig)
      except BincodeError:
        fail getCurrentExceptionMsg()
      blk = decodeSyncBlock(genesisWire).get
    check blockId(blk.header) == blockId(genesis.header)

  test "decodeSyncBlock bounds the uncle count":
    let
      genesis = testGenesisBlock()
      uncle = SignedHeader(header: genesis.header, signature: DefaultEd25519Signature)
    template wire(uncles: seq[SignedHeader]): seq[byte] =
      encode(
        Block(header: genesis.header, signature: genesis.signature,
              uncleHeaders: UncleHeaders(uncles), txs: BlockTxs(@[])),
        cryptarchiaSyncBincodeConfig)
    check:
      decodeSyncBlock(wire(@[uncle, uncle, uncle, uncle])).isOk
      decodeSyncBlock(wire(@[uncle, uncle, uncle, uncle, uncle])).isErr

  test "cappedDownloadPathBlockIds returns target block when path is one hop":
    let
      sm = minimalValidSignedTx()
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = childValidBlock(genesis.header, gid, SlotNumber(1), [sm])
    check tree.addBlockToTree(b1)
    let
      b1id = blockId(b1.header)
      req = DownloadBlocksRequest(
        targetBlock: b1id,
        knownBlocks: buildKnownBlocks(newLocalTree(genesis, 1'u64), []),
      )
      sendIds = cappedDownloadPathBlockIds(tree, req)
    check:
      sendIds.len == 1
      sendIds[0] == b1id

  test "cappedDownloadPathBlockIds caps batch at MaxRequestBlocks":
    let
      genesis = testGenesisBlock()
      tree = newLocalTree(genesis, 1'u64)
      tipId = extendChainAfterGenesis(tree, genesis, MaxRequestBlocks + 5)
      req = DownloadBlocksRequest(
        targetBlock: tipId,
        knownBlocks: buildKnownBlocks(newLocalTree(genesis, 1'u64), []),
      )
      sendIds = cappedDownloadPathBlockIds(tree, req)
    check:
      sendIds.len == MaxRequestBlocks
      sendIds[0] != tipId

  asyncTest "downloadBlocks paginates over MaxRequestBlocks carrying latestDownloadedId":
    const k = uint64(MaxRequestBlocks + 10)
    let
      genesis = testGenesisBlock()
      serverChain = initTestChain(genesis, securityParam = k)
      clientChain = initTestChain(genesis, securityParam = k)
      # Keep client's localTip on a taller fork across batch 1 so batch 2 relies on additionalBlocks.
      clientForkTip = extendChainAfterGenesis(clientChain.localTree, genesis, MaxRequestBlocks + 2)
      targetTip = extendChainAfterGenesis(
        serverChain.localTree, genesis, MaxRequestBlocks + 5, startSlot = 2)
    check:
      clientChain.localTree.localTipId == clientForkTip
      not clientChain.localTree.hasBlock(targetTip)
    withSyncPair(serverChain, clientChain):
      let res = await downloadBlocks(clientSyncer, server.peerInfo.peerId, targetTip)
      check:
        res.reached
        res.latestDownloadedId.get == targetTip
        clientChain.localTree.localTipId == targetTip

  asyncTest "downloadBlocks returns false when target block is unknown on server":
    let genesis = testGenesisBlock()
    withSyncPair(initTestChain(genesis), initTestChain(genesis)):
      check not (await downloadBlocks(
        clientSyncer, server.peerInfo.peerId, exampleBlockId(0x99))).reached

  asyncTest "downloadBlocks aborts without looping when peer only has already-applied blocks":
    const k = uint64(MaxRequestBlocks + 10)
    let
      genesis = testGenesisBlock()
      serverChain = initTestChain(genesis, securityParam = k)
      clientChain = initTestChain(genesis, securityParam = k)
      clientForkTip = extendChainAfterGenesis(clientChain.localTree, genesis, MaxRequestBlocks + 2)
      targetTip = extendChainAfterGenesis(
        serverChain.localTree, genesis, MaxRequestBlocks + 1, startSlot = 2)
    discard extendChainAfterGenesis(clientChain.localTree, genesis, MaxRequestBlocks, startSlot = 2)
    check:
      clientChain.localTree.localTipId == clientForkTip
      not clientChain.localTree.hasBlock(targetTip)
    withSyncPair(serverChain, clientChain):
      let res = await downloadBlocks(clientSyncer, server.peerInfo.peerId, targetTip)
      check:
        not res.reached
        res.latestDownloadedId.isNone

  asyncTest "sync handler rejects DownloadBlocksRequest when additionalBlocks exceeds MaxKnownAdditionalBlocks":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      b1 = childValidBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
      serverChain = initTestChain(genesis)
      clientChain = initTestChain(genesis)
    check serverChain.localTree.addBlockToTree(b1)
    proc queryFirstFrame(sw: Switch, peer: PeerId, extraCount: int): Future[DownloadBlocksResponseKind] {.async.} =
      let
        req = RequestMessage(
          kind: rmDownloadBlocksRequest,
          downloadBlocksRequest: DownloadBlocksRequest(
            targetBlock: b1id,
            knownBlocks: KnownBlocks(
              localTip: gid,
              latestImmutableBlock: gid,
              additionalBlocks: newSeq[BlockId](extraCount),
            ),
          ),
        )
        conn = await sw.dial(peer, testChainSyncProtocol)
      defer:
        await noCancel conn.close()
      await writeCryptarchiaPrefixedInner(conn, encode(req, cryptarchiaSyncBincodeConfig))
      let inner = (await readCryptarchiaPrefixedInner(conn)).get()
      decode(inner, DownloadBlocksResponse, cryptarchiaSyncBincodeConfig).kind
    withSyncPair(serverChain, clientChain):
      check:
        (await queryFirstFrame(client, server.peerInfo.peerId, MaxKnownAdditionalBlocks)) == dbrBlock
        (await queryFirstFrame(client, server.peerInfo.peerId, MaxKnownAdditionalBlocks + 1)) == dbrFailure

suite "sync/initial_block_download (GetTip)":
  asyncTest "sendGetTipRequest round-trips over mounted sync handler":
    let
      genesis = testGenesisBlock()
      serverChain = initTestChain(genesis)
    withSyncPair(serverChain, initTestChain(genesis)):
      let tipResp = (await sendGetTipRequest(clientSyncer, server.peerInfo.peerId, 1.seconds)).get()
      check:
        tipResp.kind == gtrTip
        tipResp.tipData == serverChain.localTree.localTip()

  asyncTest "sync handler rejects GetTip and DownloadBlocks requests while IBD is in progress":
    let
      genesis = testGenesisBlock()
      serverChain = initTestChain(genesis)
      clientChain = initTestChain(genesis)
      gate = Future[void].Raising([CancelledError]).init("test.stalled_ibd")
    defer:
      gate.cancelSoon()
    withSwitches:
      let
        (server, client) = (startSwitch(), startSwitch())
        serverSyncer = Syncer.init(
          server, BlockProcessor.new(serverChain), testChainSyncProtocol, peerProvider())
      mountStalledServer(client, gate)
      await server.connect(client.peerInfo.peerId, client.peerInfo.addrs, forceDial = true)
      serverSyncer.start(nil, nil, peerProvider(client.peerInfo.peerId))
      try:
        withClientSyncerOn(client, clientChain, nil):
          let tipResp = (await sendGetTipRequest(
            clientSyncer, server.peerInfo.peerId, 1.seconds)).get()
          check:
            tipResp.kind == gtrFailure
            not (await downloadBlocks(
              clientSyncer, server.peerInfo.peerId, exampleBlockId(0x88))).reached
      finally:
        await serverSyncer.stop()

suite "sync/initial_block_download (IBD requester loop)":
  asyncTest "initialBlockDownload with no configured peers completes without raising":
    await initialBlockDownload(Syncer(), nil)

  asyncTest "initialBlockDownload when peerProvider is nil or no peers are connected raises IBDFailure":
    expect IBDFailure:
      await initialBlockDownload(Syncer(), peerProvider())
    expect IBDFailure:
      await initialBlockDownload(
        Syncer(peerProvider: peerProvider()), peerProvider(), roundDelay = 1.milliseconds)

  asyncTest "initialBlockDownload succeeds when peer tip is already in local tree":
    let genesis = testGenesisBlock()
    withSyncPair(initTestChain(genesis), initTestChain(genesis)):
      await initialBlockDownload(clientSyncer, peerProvider(server.peerInfo.peerId))

  asyncTest "initialBlockDownload raises when sync handler is not mounted":
    withSwitches:
      let (server, client) = (startSwitch(), startSwitch())
      withClientSyncerOn(client, initTestChain(testGenesisBlock()), peerProvider(server.peerInfo.peerId)):
        await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)
        expect IBDFailure:
          await initialBlockDownload(
            clientSyncer, peerProvider(server.peerInfo.peerId), roundDelay = 1.milliseconds)

  asyncTest "initialBlockDownload succeeds when peer chain is taller and download sends blocks":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      b1 = childValidBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
      serverChain = initTestChain(genesis)
      clientChain = initTestChain(genesis)
    check:
      serverChain.localTree.addBlockToTree(b1)
      serverChain.localTree.localTipId == b1id
    withSyncPair(serverChain, clientChain):
      await initialBlockDownload(
        clientSyncer, peerProvider(server.peerInfo.peerId), roundDelay = 10.milliseconds)
      check:
        clientChain.localTree.hasBlock(b1id)
        clientChain.localTree.localTipId == b1id

  asyncTest "initialBlockDownload continues gracefully when downloaded block is in flight":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      b1Valid = childValidBlock(genesis.header, gid, SlotNumber(1), [])
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
      b2Valid = childValidBlock(b1.header, b1id, SlotNumber(2), [])
      b2 = childBlock(b1.header, b1id, SlotNumber(2), [])
      b2id = blockId(b2.header)
      serverChain = initTestChain(genesis)
      clientChain = initTestChain(genesis)
    check:
      serverChain.localTree.addBlockToTree(b1Valid)
      serverChain.localTree.addBlockToTree(b2Valid)
    withSyncPair(serverChain, clientChain):
      # Queue b1 ahead of time so it is in-flight when IBD processes the downloaded batch
      let fGossip = clientSyncer.processor.addBlock(b1, b1id)
      await initialBlockDownload(
        clientSyncer, peerProvider(server.peerInfo.peerId), roundDelay = 10.milliseconds)
      check:
        (await fGossip).isOk
        clientChain.localTree.hasBlock(b1id)
        clientChain.localTree.hasBlock(b2id)
        clientChain.localTree.localTipId == b2id

  asyncTest "initialBlockDownload queries GetTip from bootstrapPeerProvider and downloads from peerProvider":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      b1 = childValidBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
      trustedChain = initTestChain(genesis)
      downloadChain = initTestChain(genesis)
      clientChain = initTestChain(genesis)
    check:
      trustedChain.localTree.addBlockToTree(b1)
      downloadChain.localTree.addBlockToTree(b1)

    withSwitches:
      let (trustedPeer, failingPeer, downloadPeer, client) =
        (startSwitch(), startSwitch(), startSwitch(), startSwitch())
      mountTestServer(trustedPeer, trustedChain)
      mountTestServer(downloadPeer, downloadChain)
      var calls = 0
      let dynamicPeers: PeerProvider = proc(): seq[PeerId] =
        inc calls
        if calls == 1:
          @[failingPeer.peerInfo.peerId]
        else:
          @[failingPeer.peerInfo.peerId, downloadPeer.peerInfo.peerId]
      withClientSyncerOn(client, clientChain, dynamicPeers):
        await client.connect(trustedPeer.peerInfo.peerId, trustedPeer.peerInfo.addrs, forceDial = true)
        await client.connect(failingPeer.peerInfo.peerId, failingPeer.peerInfo.addrs, forceDial = true)
        await client.connect(downloadPeer.peerInfo.peerId, downloadPeer.peerInfo.addrs, forceDial = true)
        await initialBlockDownload(
          clientSyncer,
          peerProvider(failingPeer.peerInfo.peerId, trustedPeer.peerInfo.peerId),
          roundDelay = 10.milliseconds,
        )
        check:
          calls >= 2
          clientChain.localTree.hasBlock(b1id)
          clientChain.localTree.localTipId == b1id

  asyncTest "initialBlockDownload retries GetTip with backoff on staggered server startup":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      b1 = childValidBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
      serverChain = initTestChain(genesis)
      clientChain = initTestChain(genesis)
    check serverChain.localTree.addBlockToTree(b1)

    var tipQueries = 0
    withSwitches:
      let
        (server, client) = (startSwitch(), startSwitch())
        bootstrapPeers: PeerProvider = proc(): seq[PeerId] =
          inc tipQueries
          if tipQueries == 2:
            try:
              mountTestServer(server, serverChain)
            except LPError as exc:
              raiseAssert exc.msg
          @[server.peerInfo.peerId]
      withClientSyncerOn(client, clientChain, peerProvider(server.peerInfo.peerId)):
        await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)
        await initialBlockDownload(clientSyncer, bootstrapPeers, roundDelay = 5.milliseconds)
        check:
          tipQueries == 3
          clientChain.localTree.hasBlock(b1id)
          clientChain.localTree.localTipId == b1id

  asyncTest "initialBlockDownload times out stalled peer on GetTip and download and fails over":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      b1 = childValidBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
      goodChain = initTestChain(genesis)
      clientChain = initTestChain(genesis)
      gate = Future[void].Raising([CancelledError]).init("test.stalled_peer")
    defer:
      gate.cancelSoon()
    check goodChain.localTree.addBlockToTree(b1)

    withSwitches:
      let
        (stalledPeer, goodPeer, client) = (startSwitch(), startSwitch(), startSwitch())
        peers = peerProvider(stalledPeer.peerInfo.peerId, goodPeer.peerInfo.peerId)
      mountStalledServer(stalledPeer, gate)
      mountTestServer(goodPeer, goodChain)
      withClientSyncerOn(client, clientChain, peers):
        await client.connect(stalledPeer.peerInfo.peerId, stalledPeer.peerInfo.addrs, forceDial = true)
        await client.connect(goodPeer.peerInfo.peerId, goodPeer.peerInfo.addrs, forceDial = true)
        await initialBlockDownload(
          clientSyncer,
          peers,
          roundDelay = 5.milliseconds,
          tipTimeout = 50.milliseconds,
          streamTimeout = 50.milliseconds,
        )
        check:
          clientChain.localTree.hasBlock(b1id)
          clientChain.localTree.localTipId == b1id

  asyncTest "initialBlockDownload syncs diverging forks from multiple bootstrap peers":
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      a1 = childValidBlock(genesis.header, gid, SlotNumber(1), [])
      a2 = childValidBlock(a1.header, blockId(a1.header), SlotNumber(2), [])
      idA2 = blockId(a2.header)
      b1 = childValidBlock(genesis.header, gid, SlotNumber(2), [])
      b2 = childValidBlock(b1.header, blockId(b1.header), SlotNumber(3), [])
      b3 = childValidBlock(b2.header, blockId(b2.header), SlotNumber(4), [])
      idB3 = blockId(b3.header)
      peer1Chain = initTestChain(genesis, securityParam = 5)
      peer2Chain = initTestChain(genesis, securityParam = 5)
      clientChain = initTestChain(genesis, securityParam = 5)
    check:
      peer1Chain.localTree.addBlockToTree(a1)
      peer1Chain.localTree.addBlockToTree(a2)
      peer2Chain.localTree.addBlockToTree(b1)
      peer2Chain.localTree.addBlockToTree(b2)
      peer2Chain.localTree.addBlockToTree(b3)

    withSwitches:
      let
        (peer1, peer2, client) = (startSwitch(), startSwitch(), startSwitch())
        peers = peerProvider(peer1.peerInfo.peerId, peer2.peerInfo.peerId)
      mountTestServer(peer1, peer1Chain)
      mountTestServer(peer2, peer2Chain)
      withClientSyncerOn(client, clientChain, peers):
        await client.connect(peer1.peerInfo.peerId, peer1.peerInfo.addrs, forceDial = true)
        await client.connect(peer2.peerInfo.peerId, peer2.peerInfo.addrs, forceDial = true)
        await initialBlockDownload(clientSyncer, peers, roundDelay = 5.milliseconds)
        check:
          clientChain.localTree.hasBlock(idA2)
          clientChain.localTree.hasBlock(idB3)
          clientChain.localTree.localTipId == idB3

  asyncTest "initialBlockDownload carries latestDownloadedId to next peer on failover":
    const
      k = uint64(MaxRequestBlocks + 10)
      s129 = SlotNumber(uint64(MaxRequestBlocks + 2))
      s130 = SlotNumber(uint64(MaxRequestBlocks + 3))
    let
      genesis = testGenesisBlock()
      badChain = initTestChain(genesis, securityParam = k)
      goodChain = initTestChain(genesis, securityParam = k)
      clientChain = initTestChain(genesis, securityParam = k)
      # Keep client's localTip on a taller fork after batch 1 (128 blocks) so goodPeer needs additionalBlocks.
      clientForkTip = extendChainAfterGenesis(clientChain.localTree, genesis, MaxRequestBlocks + 1)
      idB128 = extendChainAfterGenesis(badChain.localTree, genesis, MaxRequestBlocks, startSlot = 2)
      b128Hdr = badChain.localTree.getBlock(idB128).get.header
      b129Bad = mkChildValidBlock(b128Hdr, idB128, s129)
      b129Good = childValidBlock(b128Hdr, idB128, s129, [])
      idB129 = blockId(b129Good.header)
      b130Bad = mkChildValidBlock(b129Bad.header, idB129, s130)
      b130Good = childValidBlock(b129Good.header, idB129, s130, [])
      targetTip = blockId(b130Good.header)
    discard extendChainAfterGenesis(goodChain.localTree, genesis, MaxRequestBlocks, startSlot = 2)
    check:
      clientChain.localTree.localTipId == clientForkTip
      badChain.localTree.addBlockToTree(b129Bad)
      badChain.localTree.addBlockToTree(b130Bad)
      goodChain.localTree.addBlockToTree(b129Good)
      goodChain.localTree.addBlockToTree(b130Good)

    withSwitches:
      let (badPeer, goodPeer, client) = (startSwitch(), startSwitch(), startSwitch())
      mountTestServer(badPeer, badChain)
      mountTestServer(goodPeer, goodChain)
      withClientSyncerOn(
        client, clientChain, peerProvider(badPeer.peerInfo.peerId, goodPeer.peerInfo.peerId)
      ):
        await client.connect(badPeer.peerInfo.peerId, badPeer.peerInfo.addrs, forceDial = true)
        await client.connect(goodPeer.peerInfo.peerId, goodPeer.peerInfo.addrs, forceDial = true)
        await initialBlockDownload(
          clientSyncer, peerProvider(goodPeer.peerInfo.peerId), roundDelay = 5.milliseconds)
        check clientChain.localTree.localTipId == targetTip

suite "LBP2PNode cryptarchia IBD at startup":
  asyncTest "bootstrap peer serves chain; client syncs chain and fires onIbdComplete on start()":
    let
      genesis = testGenesisBlock()
      chainBootstrap = initTestChain(genesis)
      tipId = extendChainAfterGenesis(chainBootstrap.localTree, genesis, 10)
      chainClient = initTestChain(genesis)
      peers = await createBootstrapPeers()
    mountTestServer(peers.listener.switch, chainBootstrap)

    var ibdCompleted = false
    try:
      withClientSyncerOn(
        peers.dialer.switch,
        chainClient,
        proc(): seq[PeerId] = peers.dialer.connectedPeerIds(),
      ):
        await peers.listener.start()
        await peers.dialer.start()
        discard await peers.dialer.waitForBootstrapPeers()
        clientSyncer.start(
          proc() {.gcsafe, raises: [].} = ibdCompleted = true,
          nil,
          proc(): seq[PeerId] = peers.dialer.connectedBootstrapPeerIds(),
        )
        check:
          waitUntil(ibdCompleted, 5.seconds)
          chainClient.localTree.localTipId == tipId
    finally:
      await allFutures(peers.dialer.stop(), peers.listener.stop())

{.pop.}
