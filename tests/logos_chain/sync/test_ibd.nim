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
  ../../../logos_chain/core/types,
  ../../../logos_chain/chain/[chain, local_tree],
  ../../../logos_chain/sync/[types, sync_client, sync_server, syncer],
  ./helpers,
  ../../testutil
from ../../../logos_chain/core/mantle/primitives import SlotNumber

template peerProvider(peers: varargs[PeerId]): PeerProvider =
  (proc(): seq[PeerId] = @peers)

proc runLbp2pIbdSyncTest(extraBlocks: int) {.async.} =
  let genesis = createGenesisBlock(testValidGenesisTx())

  var chainBootstrap = initTestChain(genesis)
  let tipId = extendChainAfterGenesis(chainBootstrap.localTree, genesis, extraBlocks)
  check chainBootstrap.localTree.localTipId == tipId

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
        proc(): seq[PeerId] = peers.dialer.connectedBootstrapPeerIds(),
      )

      check waitUntil(peers.dialer.switch.isConnected(peers.listenerPeerId))
      check waitUntil(chainClient.localTree.hasBlock(tipId), chronos.milliseconds(waitAttempts * 100))
      check chainClient.localTree.localTipId == tipId
  finally:
    await peers.dialer.stop()
    await peers.listener.stop()

suite "sync/initial_block_download (download blocks)":
  test "decodeSyncBlock roundtrip (genesis block on sync wire)":
    let
      genesis = createGenesisBlock(testValidGenesisTx())
      genesisWire = try:
        encode(genesis, cryptarchiaSyncBincodeConfig)
      except BincodeError:
        fail getCurrentExceptionMsg()
    let blk = decodeSyncBlock(genesisWire).get
    check blockId(blk.header) == blockId(genesis.header)

  test "decodeSyncBlock bounds the uncle count":
    let
      genesis = createGenesisBlock(testValidGenesisTx())
      uncle = SignedHeader(header: genesis.header, signature: DefaultEd25519Signature)
    template wire(uncles: seq[SignedHeader]): seq[byte] =
      encode(
        Block(header: genesis.header, signature: genesis.signature,
              uncleHeaders: UncleHeaders(uncles), txs: BlockTxs(@[])),
        cryptarchiaSyncBincodeConfig)
    check decodeSyncBlock(wire(@[uncle, uncle, uncle, uncle])).isOk
    check decodeSyncBlock(wire(@[uncle, uncle, uncle, uncle, uncle])).isErr

  test "cappedDownloadPathBlockIds returns target block when path is one hop":
    let
      sm = minimalValidSignedTx()
      genesis = createGenesisBlock(testValidGenesisTx())
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
    let sendIds = cappedDownloadPathBlockIds(tree, req)
    check sendIds.len == 1
    check sendIds[0] == b1id

  test "cappedDownloadPathBlockIds caps batch at MaxRequestBlocks":
    let
      genesis = createGenesisBlock(testValidGenesisTx())
      tree = newLocalTree(genesis, 1'u64)
      tipId = extendChainAfterGenesis(tree, genesis, MaxRequestBlocks + 5)
      req = DownloadBlocksRequest(
        targetBlock: tipId,
        knownBlocks: buildKnownBlocks(newLocalTree(genesis, 1'u64), []),
      )
    let sendIds = cappedDownloadPathBlockIds(tree, req)
    check sendIds.len == MaxRequestBlocks
    check sendIds[0] != tipId

  test "downloadBlocksResponsesForRequest recovers blocks from handler-shaped response":
    let
      sm = minimalValidSignedTx()
      genesis = createGenesisBlock(testValidGenesisTx())
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      b1 = childValidBlock(genesis.header, gid, SlotNumber(1), [sm])
    check tree.addBlockToTree(b1)
    let req = DownloadBlocksRequest(
      targetBlock: blockId(b1.header),
      knownBlocks: buildKnownBlocks(newLocalTree(genesis, 1'u64), []),
    )
    let msgs = downloadBlocksResponsesForRequest(tree, req)
    check msgs.len == 2
    check msgs[0].kind == dbrBlock
    let blk = decodeSyncBlock(msgs[0].downloadedBlock).get
    check blockId(blk.header) == blockId(b1.header)
    check msgs[1].kind == dbrNoMoreBlocks

  asyncTest "sendDownloadBlocksRequest round-trips over mounted sync handler":
    let
      sm = minimalValidSignedTx()
      genesis = createGenesisBlock(testValidGenesisTx())
      gid = blockId(genesis.header)
      b1 = childValidBlock(genesis.header, gid, SlotNumber(1), [sm])
      serverChain = initTestChain(genesis)
    check serverChain.localTree.addBlockToTree(b1)
    let
      b1id = blockId(b1.header)
      clientChain = initTestChain(genesis)
      req = DownloadBlocksRequest(
        targetBlock: b1id, knownBlocks: buildKnownBlocks(clientChain.localTree, []))
    withSyncPair(serverChain, clientChain):
      let
        blks = (await sendDownloadBlocksRequest(
          clientSyncer, server.peerInfo.peerId, req)).get()
        expectedMsgs = downloadBlocksResponsesForRequest(serverChain.localTree, req)
        expectedBlk = decodeSyncBlock(expectedMsgs[0].downloadedBlock).get
      check:
        blks.len == 1
        blockId(blks[0].header) == b1id
        blockDownloadWireEqual(blks[0], expectedBlk)

  asyncTest "sendDownloadBlocksRequest returns none when target block is unknown on server":
    let
      genesis = createGenesisBlock(testValidGenesisTx())
      serverChain = initTestChain(genesis)
      clientChain = initTestChain(genesis)
      unknownTarget = exampleBlockId(0x99)
      req = DownloadBlocksRequest(
        targetBlock: unknownTarget,
        knownBlocks: buildKnownBlocks(clientChain.localTree, []),
      )
    withSyncPair(serverChain, clientChain):
      let res = await sendDownloadBlocksRequest(
        clientSyncer, server.peerInfo.peerId, req)
      check res.isNone

suite "sync/initial_block_download (GetTip)":
  asyncTest "sendGetTipRequest round-trips over mounted sync handler":
    let
      genesis = createGenesisBlock(testValidGenesisTx())
      serverChain = initTestChain(genesis)
    withSyncPair(serverChain, initTestChain(genesis)):
      let tipResp = (await sendGetTipRequest(clientSyncer, server.peerInfo.peerId)).get()
      check tipResp.kind == gtrTip
      check tipResp.tipData == serverChain.localTree.localTip()

suite "sync/initial_block_download (IBD requester loop)":
  asyncTest "initialBlockDownload with no configured peers completes without raising":
    let genesis = createGenesisBlock(testValidGenesisTx())
    withClientSyncer(initTestChain(genesis)):
      await initialBlockDownload(clientSyncer, nil)

  asyncTest "initialBlockDownload when no configured peers are connected raises IBDFailure":
    let genesis = createGenesisBlock(testValidGenesisTx())
    withClientSyncer(initTestChain(genesis)):
      expect IBDFailure:
        await initialBlockDownload(clientSyncer, peerProvider())

  asyncTest "initialBlockDownload succeeds when peer tip is already in local tree":
    let genesis = createGenesisBlock(testValidGenesisTx())
    withSyncPair(initTestChain(genesis), initTestChain(genesis)):
      await initialBlockDownload(clientSyncer, peerProvider(server.peerInfo.peerId))

  asyncTest "initialBlockDownload raises when peer chain is taller but sync handler is not mounted":
    let
      sm = minimalValidSignedTx()
      genesis = createGenesisBlock(testValidGenesisTx())
      gid = blockId(genesis.header)
      b1 = childValidBlock(genesis.header, gid, SlotNumber(1), [sm])
      serverChain = initTestChain(genesis)
    check serverChain.localTree.addBlockToTree(b1)
    check serverChain.localTree.localTipId == blockId(b1.header)

    let server = await startQuicTestSwitch()
    try:
      withClientSyncer(initTestChain(genesis)):
        await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)
        expect IBDFailure:
          await initialBlockDownload(clientSyncer, peerProvider(server.peerInfo.peerId))
    finally:
      await server.stop()

  asyncTest "initialBlockDownload succeeds when peer chain is taller and download sends blocks":
    let
      genesis = createGenesisBlock(testValidGenesisTx())
      gid = blockId(genesis.header)
      b1 = childValidBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
      serverChain = initTestChain(genesis)
      clientChain = initTestChain(genesis)
    check serverChain.localTree.addBlockToTree(b1)
    check serverChain.localTree.localTipId == b1id
    withSyncPair(serverChain, clientChain):
      await initialBlockDownload(clientSyncer, peerProvider(server.peerInfo.peerId))
      check clientChain.localTree.hasBlock(b1id)
      check clientChain.localTree.localTipId == b1id

  asyncTest "initialBlockDownload continues gracefully when downloaded block is in flight":
    let
      genesis = createGenesisBlock(testValidGenesisTx())
      gid = blockId(genesis.header)
      b1Valid = childValidBlock(genesis.header, gid, SlotNumber(1), [])
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
      b2Valid = childValidBlock(b1.header, b1id, SlotNumber(2), [])
      b2 = childBlock(b1.header, b1id, SlotNumber(2), [])
      b2id = blockId(b2.header)
      serverChain = initTestChain(genesis)
      clientChain = initTestChain(genesis)
    check serverChain.localTree.addBlockToTree(b1Valid)
    check serverChain.localTree.addBlockToTree(b2Valid)
    withSyncPair(serverChain, clientChain):
      # Queue b1 ahead of time so it is in-flight when IBD processes the downloaded batch
      let fGossip = clientSyncer.processor.addBlock(b1, b1id)
      await initialBlockDownload(clientSyncer, peerProvider(server.peerInfo.peerId))
      check (await fGossip).isOk
      check clientChain.localTree.hasBlock(b1id)
      check clientChain.localTree.hasBlock(b2id)
      check clientChain.localTree.localTipId == b2id

  asyncTest "initialBlockDownload fails over to secondary peer when primary peer fails":
    let
      genesis = createGenesisBlock(testValidGenesisTx())
      gid = blockId(genesis.header)
      b1 = childValidBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
      serverChain2 = initTestChain(genesis)
      clientChain = initTestChain(genesis)
    check serverChain2.localTree.addBlockToTree(b1)

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
          peerProvider(server1.peerInfo.peerId, server2.peerInfo.peerId),
        )
        check clientChain.localTree.hasBlock(b1id)
        check clientChain.localTree.localTipId == b1id
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
