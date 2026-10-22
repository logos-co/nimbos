# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  chronos,
  chronos/unittest2/asynctests,
  unittest2,
  bincode,
  libp2p/[switch, peerid],
  ../../../logos_chain/networking/network,
  ../../../logos_chain/core/[types, local_tree],
  ../../../logos_chain/chain/[genesis, chain],
  ../../../logos_chain/sync/[types, ibd_client, ibd_server, syncer],
  ./helpers,
  ../../testutil
from ../../../logos_chain/core/mantle/primitives import SlotNumber

template peerProvider(peers: varargs[PeerId]): PeerProvider =
  (proc(): seq[PeerId] = @peers)

proc runLbp2pIbdSyncTest(extraBlocks: int) {.async.} =
  let genesis = createGenesisBlock(testGenesisTx()).get

  var chainBootstrap = initTestChain(genesis)
  let tipId = extendChainAfterGenesis(chainBootstrap.consensus.localTree, genesis, extraBlocks)
  chainBootstrap.consensus.tryUpdateTip(tipId)
  check chainBootstrap.consensus.canonicalTip.tip == tipId

  let
    chainClient = initTestChain(genesis)
    peers = await createBootstrapPeers()
    waitAttempts = 150 + extraBlocks * 5
  discard mountTestServer(peers.listener.switch, chainBootstrap)

  try:
    withClientSyncerOn(peers.dialer.switch, chainClient):
      await peers.listener.start()
      await peers.dialer.start()
      discard await peers.dialer.waitForBootstrapPeers()
      clientSyncer.start(
        nil,
        nil,
        Opt.some(proc(): seq[PeerId] = peers.dialer.connectedBootstrapPeerIds()),
      )

      check waitUntil(peers.dialer.switch.isConnected(peers.listenerPeerId))
      check waitUntil(chainClient.consensus.hasBlock(tipId), chronos.milliseconds(waitAttempts * 100))
      check clientSyncer.processor.consensus.canonicalTip.tip == tipId
  finally:
    await peers.dialer.stop()
    await peers.listener.stop()

suite "sync/initial_block_download (download blocks)":
  test "decodeBlocksFromDownloadResponses roundtrip (genesis wrapped in dbrBlock)":
    let
      genesis = createGenesisBlock(testGenesisTx()).get
      genesisWire = try:
        encode(genesis, cryptarchiaSyncBincodeConfig)
      except BincodeError:
        fail getCurrentExceptionMsg()
    let blks = decodeBlocksFromDownloadResponses(@[
      DownloadBlocksResponse(kind: dbrBlock, downloadedBlock: genesisWire),
    ]).get()
    check blks.len == 1
    check blockId(blks[0].header) == blockId(genesis.header)

  test "decodeBlocksFromDownloadResponses bounds the uncle count":
    let
      genesis = createGenesisBlock(testGenesisTx()).get
      uncle = SignedHeader(header: genesis.header, signature: DefaultEd25519Signature)
    template response(uncles: seq[SignedHeader]): DownloadBlocksResponse =
      DownloadBlocksResponse(
        kind: dbrBlock,
        downloadedBlock: encode(
          Block(header: genesis.header, signature: genesis.signature,
                uncleHeaders: UncleHeaders(uncles), txs: BlockTxs(@[])),
          cryptarchiaSyncBincodeConfig))
    check decodeBlocksFromDownloadResponses(@[response(@[uncle, uncle, uncle, uncle])]).get.len == 1
    check decodeBlocksFromDownloadResponses(@[response(@[uncle, uncle, uncle, uncle, uncle])]).isNone

  test "cappedDownloadPathBlockIds returns target block when path is one hop":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      cs = ConsensusState.init(genesis, securityParam = 1, densitySlotWindow = 100, forkChoiceRule = ForkChoiceRule.Bootstrap)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    check cs.localTree.addBlockToTree(b1)
    let
      b1id = blockId(b1.header)
      req = DownloadBlocksRequest(
        targetBlock: b1id,
        knownBlocks: KnownBlocks(
          localTip: gid,
          latestImmutableBlock: gid,
        ),
      )
    let sendIds = cappedDownloadPathBlockIds(cs, req)
    check sendIds.len == 1
    check sendIds[0] == b1id

  test "cappedDownloadPathBlockIds caps batch at MaxRequestBlocks":
    let
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      cs = ConsensusState.init(genesis, securityParam = 1, densitySlotWindow = 100, forkChoiceRule = ForkChoiceRule.Bootstrap)
      tipId = extendChainAfterGenesis(cs.localTree, genesis, MaxRequestBlocks + 5)
      req = DownloadBlocksRequest(
        targetBlock: tipId,
        knownBlocks: KnownBlocks(
          localTip: gid,
          latestImmutableBlock: gid,
        ),
      )
    let sendIds = cappedDownloadPathBlockIds(cs, req)
    check sendIds.len == MaxRequestBlocks
    check sendIds[0] != tipId

  test "decodeBlocksFromDownloadResponses recovers blocks from handler-shaped response":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      cs = ConsensusState.init(genesis, securityParam = 1, densitySlotWindow = 100, forkChoiceRule = ForkChoiceRule.Bootstrap)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    check cs.localTree.addBlockToTree(b1)
    let req = DownloadBlocksRequest(
      targetBlock: blockId(b1.header),
      knownBlocks: KnownBlocks(
        localTip: blockId(genesis.header),
        latestImmutableBlock: blockId(genesis.header),
      ),
    )
    let
      msgs = downloadBlocksResponsesForRequest(cs, req)
      blks = decodeBlocksFromDownloadResponses(msgs).get()
    check blks.len == 1
    check blockId(blks[0].header) == blockId(b1.header)

  asyncTest "sendDownloadBlocksRequest round-trips over mounted sync handler":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
      serverChain = initTestChain(genesis)
    check serverChain.consensus.addBlockAndTryUpdateTip(b1)
    let
      b1id = blockId(b1.header)
      clientChain = initTestChain(genesis)
    withSyncPair(serverChain, clientChain):
      let
        req = DownloadBlocksRequest(
          targetBlock: b1id, knownBlocks: buildKnownBlocks(clientSyncer.processor.consensus))
        blks = (await sendDownloadBlocksRequest(
          clientSyncer, server.peerInfo.peerId, req)).get()
        expectedBlks = decodeBlocksFromDownloadResponses(
          downloadBlocksResponsesForRequest(serverChain.consensus, req)).get()
      check:
        blks.len == expectedBlks.len
        blks.len == 1
        blockId(blks[0].header) == b1id
        blockDownloadWireEqual(blks[0], expectedBlks[0])

suite "sync/initial_block_download (GetTip)":
  asyncTest "sendGetTipRequest round-trips over mounted sync handler":
    let
      genesis = createGenesisBlock(testGenesisTx()).get
      serverChain = initTestChain(genesis)
    withSyncPair(serverChain, initTestChain(genesis)):
      let tipResp = (await sendGetTipRequest(clientSyncer, server.peerInfo.peerId)).get()
      check tipResp.kind == gtrTip
      check tipResp.tipData == serverChain.consensus.canonicalTip

suite "sync/initial_block_download (IBD requester loop)":
  asyncTest "initialBlockDownload with no configured peers completes without raising":
    let genesis = createGenesisBlock(testGenesisTx()).get
    withClientSyncer(initTestChain(genesis)):
      await initialBlockDownload(clientSyncer, Opt.none(PeerProvider))

  asyncTest "initialBlockDownload when no configured peers are connected raises IBDFailure":
    let genesis = createGenesisBlock(testGenesisTx()).get
    withClientSyncer(initTestChain(genesis)):
      expect IBDFailure:
        await initialBlockDownload(clientSyncer, Opt.some(peerProvider()))

  asyncTest "initialBlockDownload succeeds when peer tip is already in local tree":
    let genesis = createGenesisBlock(testGenesisTx()).get
    withSyncPair(initTestChain(genesis), initTestChain(genesis)):
      await initialBlockDownload(clientSyncer, Opt.some(peerProvider(server.peerInfo.peerId)))

  asyncTest "initialBlockDownload raises when peer chain is taller but sync handler is not mounted":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
      b1Id = blockId(b1.header)
      serverChain = initTestChain(genesis)
    check:
      serverChain.consensus.addBlockAndTryUpdateTip(b1)
      serverChain.consensus.canonicalTip.tip == b1Id

    let server = await startQuicTestSwitch()
    try:
      withClientSyncer(initTestChain(genesis)):
        await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)
        expect IBDFailure:
          await initialBlockDownload(clientSyncer, Opt.some(peerProvider(server.peerInfo.peerId)))
    finally:
      await server.stop()

  asyncTest "initialBlockDownload succeeds when peer chain is taller and download sends blocks":
    let
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
      serverChain = initTestChain(genesis)
      clientChain = initTestChain(genesis)
    check:
      serverChain.consensus.addBlockAndTryUpdateTip(b1)
      serverChain.consensus.canonicalTip.tip == b1id
    withSyncPair(serverChain, clientChain):
      await initialBlockDownload(clientSyncer, Opt.some(peerProvider(server.peerInfo.peerId)))
      check clientChain.consensus.hasBlock(b1id)
      check clientSyncer.processor.consensus.canonicalTip.tip == b1id

  asyncTest "initialBlockDownload continues gracefully when downloaded block is in flight":
    let
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
      b2 = childBlock(b1.header, b1id, SlotNumber(2), [])
      b2id = blockId(b2.header)
      serverChain = initTestChain(genesis)
      clientChain = initTestChain(genesis)
    check:
      serverChain.consensus.addBlockAndTryUpdateTip(b1)
      serverChain.consensus.addBlockAndTryUpdateTip(b2)
      serverChain.consensus.canonicalTip.tip == b2id
    withSyncPair(serverChain, clientChain):
      # Queue b1 via Gossip ahead of time so it is in-flight when IBD processes the downloaded batch
      let fGossip = clientSyncer.processor.addBlock(BlockSource.Gossip, b1, b1id)
      await initialBlockDownload(clientSyncer, Opt.some(peerProvider(server.peerInfo.peerId)))
      check (await fGossip).isOk
      check clientChain.consensus.hasBlock(b1id)
      check clientChain.consensus.hasBlock(b2id)
      check clientSyncer.processor.consensus.canonicalTip.tip == b2id

  asyncTest "initialBlockDownload fails over to secondary peer when primary peer fails":
    let
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
      serverChain2 = initTestChain(genesis)
      clientChain = initTestChain(genesis)
    check:
      serverChain2.consensus.addBlockAndTryUpdateTip(b1)
      serverChain2.consensus.canonicalTip.tip == b1id

    # Server 1 has no sync handler and must fail. Server 2 serves b1.
    let
      server1 = await startQuicTestSwitch()
      server2 = await startQuicTestSwitch()
    discard mountTestServer(server2, serverChain2)
    try:
      withClientSyncer(clientChain):
        await client.connect(server1.peerInfo.peerId, server1.peerInfo.addrs, forceDial = true)
        await client.connect(server2.peerInfo.peerId, server2.peerInfo.addrs, forceDial = true)
        await initialBlockDownload(
          clientSyncer,
          Opt.some(peerProvider(server1.peerInfo.peerId, server2.peerInfo.peerId)),
        )
        check clientChain.consensus.hasBlock(b1id)
        check clientSyncer.processor.consensus.canonicalTip.tip == b1id
    finally:
      await server1.stop()
      await server2.stop()

suite "LBP2PNode cryptarchia IBD at startup":
  asyncTest "bootstrap peer serves chain; client syncs 1-block taller tip on start()":
    await runLbp2pIbdSyncTest(1)

  asyncTest "client syncs 10-block bootstrap chain on start()":
    await runLbp2pIbdSyncTest(10)

  asyncTest "client syncs 50-block bootstrap chain on start()":
    await runLbp2pIbdSyncTest(50)

  asyncTest "client syncs 100-block bootstrap chain on start()":
    await runLbp2pIbdSyncTest(100)

{.pop.}
