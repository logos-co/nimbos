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
  libp2p/builders,
  ../../../logos_chain/networking/network,
  ../../../logos_chain/core/[types, local_tree],
  ../../../logos_chain/chain/[genesis, chain],
  ../../../logos_chain/sync/[types, ibd_client, ibd_server, syncer],
  ./helpers,
  ../../testutil
from ../../../logos_chain/core/mantle/primitives import SlotNumber

proc runLbp2pIbdSyncTest(
    extraBlocks: int, bootstrapPort, clientPort: Port,
) {.async.} =
  let
    sm = minimalSignedTx()
    genesis = createGenesisBlock(sm)

  var chainBootstrap = Chain.init(genesis)
  let tipId = extendChainAfterGenesis(chainBootstrap.localTree, genesis, extraBlocks)
  check chainBootstrap.localTree.localTipId == tipId

  let chainClient = Chain.init(genesis)

  let peers = await createBootstrapPeers(bootstrapPort, clientPort)
  let bootstrapSyncer = Syncer.init(
    peers.listener.switch, chainBootstrap, testChainSyncProtocol)
  bootstrapSyncer.start(@[])

  let
    clientSyncer = Syncer.init(peers.dialer.switch, chainClient, testChainSyncProtocol)
    waitAttempts = 150 + extraBlocks * 5

  try:
    await peers.dialer.start()
    clientSyncer.start(peers.dialer.bootstrapPeerIds)

    check await waitLibp2pConnected(peers.dialer.switch, peers.listenerPeerId)
    check await waitLocalTreeBlock(chainClient.localTree, tipId, waitAttempts)
    check chainClient.localTree.localTipId == tipId
  finally:
    await peers.dialer.stop()
    await peers.listener.stop()

suite "sync/initial_block_download (download blocks)":
  test "decodeBlocksFromDownloadResponses roundtrip (genesis wrapped in dbrBlock)":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      genesisWire = try:
        serializeBlockToSeq(genesis, cryptarchiaSyncBincodeConfig)
      except BincodeError, IOError:
        fail getCurrentExceptionMsg()
    let blksOpt = decodeBlocksFromDownloadResponses(@[
      DownloadBlocksResponse(kind: dbrBlock, downloadedBlock: genesisWire),
    ])
    check blksOpt.isSome and blksOpt.unsafeGet.len == 1
    check blockId(blksOpt.unsafeGet[0].header) == blockId(genesis.header)

  test "cappedDownloadPathBlockIds returns target block when path is one hop":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    check tree.addBlockToTree(b1)
    let
      b1id = blockId(b1.header)
      req = DownloadBlocksRequest(
        targetBlock: b1id,
        knownBlocks: buildKnownBlocks(newLocalTree(genesis)),
      )
    let sendIds = cappedDownloadPathBlockIds(tree, req)
    check sendIds.len == 1
    check sendIds[0] == b1id

  test "cappedDownloadPathBlockIds caps batch at MaxRequestBlocks":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      tree = newLocalTree(genesis)
      tipId = extendChainAfterGenesis(tree, genesis, MaxRequestBlocks + 5)
      req = DownloadBlocksRequest(
        targetBlock: tipId,
        knownBlocks: buildKnownBlocks(newLocalTree(genesis)),
      )
    let sendIds = cappedDownloadPathBlockIds(tree, req)
    check sendIds.len == MaxRequestBlocks
    check sendIds[0] != tipId

  test "decodeBlocksFromDownloadResponses recovers blocks from handler-shaped response":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    check tree.addBlockToTree(b1)
    let req = DownloadBlocksRequest(
      targetBlock: blockId(b1.header),
      knownBlocks: buildKnownBlocks(newLocalTree(genesis)),
    )
    let
      msgs = downloadBlocksResponsesForRequest(tree, req)
      blks = decodeBlocksFromDownloadResponses(msgs)
    check blks.isSome
    check blks.get.len == 1
    check blockId(blks.get[0].header) == blockId(b1.header)

  asyncTest "sendDownloadBlocksRequest round-trips over mounted sync handler":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    var serverChain = Chain.init(genesis)
    check serverChain.localTree.addBlockToTree(b1)
    let
      b1id = blockId(b1.header)
      clientChain = Chain.init(genesis)
      req = DownloadBlocksRequest(
        targetBlock: b1id, knownBlocks: buildKnownBlocks(clientChain.localTree))
      server = newStandardSwitch()
    let serverSyncer = Syncer.init(server, serverChain, testChainSyncProtocol)
    mountCryptarchiaSyncHandler(serverSyncer)
    let client = newStandardSwitch()
    let clientSyncer = Syncer.init(client, clientChain, testChainSyncProtocol)

    await server.start()
    await client.start()
    try:
      await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)

      let blksOpt = await sendDownloadBlocksRequest(
        clientSyncer, server.peerInfo.peerId, req)
      check blksOpt.isSome
      let expectedBlks = decodeBlocksFromDownloadResponses(
        downloadBlocksResponsesForRequest(serverChain.localTree, req)).get
      check blksOpt.get.len == expectedBlks.len
      check blksOpt.get.len == 1
      check blockId(blksOpt.get[0].header) == b1id
      check blockDownloadWireEqual(blksOpt.get[0], expectedBlks[0])
    finally:
      await client.stop()
      await server.stop()

suite "sync/initial_block_download (GetTip)":
  asyncTest "sendGetTipRequest round-trips over mounted sync handler":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
    var serverChain = Chain.init(genesis)
    let
      server = newStandardSwitch()
    let serverSyncer = Syncer.init(server, serverChain, testChainSyncProtocol)
    mountCryptarchiaSyncHandler(serverSyncer)
    let client = newStandardSwitch()
    let clientSyncer = Syncer.init(client, Chain.init(genesis), testChainSyncProtocol)

    await server.start()
    await client.start()
    try:
      await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)

      let tipOpt = await sendGetTipRequest(clientSyncer, server.peerInfo.peerId)
      check tipOpt.isSome

      let expected = Tip(
        tip: localTipId(serverChain.localTree),
        slot: SlotNumber(0),
        height: serverChain.localTree.latestImmutableHeight,
      )
      check tipOpt.get.kind == gtrTip
      check tipOpt.get.tipData == expected
    finally:
      await client.stop()
      await server.stop()

suite "sync/initial_block_download (IBD requester loop)":
  asyncTest "initialBlockDownload with no peers completes without raising":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      sw = newStandardSwitch()
    let clientSyncer = Syncer.init(sw, Chain.init(genesis), testChainSyncProtocol)
    await initialBlockDownload(clientSyncer, @[])

  asyncTest "initialBlockDownload succeeds when peer tip is already in local tree":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      server = newStandardSwitch()
    var serverChain = Chain.init(genesis)
    var clientChain = Chain.init(genesis)
    let serverSyncer = Syncer.init(server, serverChain, testChainSyncProtocol)
    mountCryptarchiaSyncHandler(serverSyncer)
    let client = newStandardSwitch()
    let clientSyncer = Syncer.init(client, clientChain, testChainSyncProtocol)

    await server.start()
    await client.start()
    try:
      await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)
      await initialBlockDownload(clientSyncer, @[server.peerInfo.peerId])
    finally:
      await client.stop()
      await server.stop()

  asyncTest "initialBlockDownload raises when peer chain is taller but sync handler is not mounted":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    var serverChain = Chain.init(genesis)
    check serverChain.localTree.addBlockToTree(b1)
    check serverChain.localTree.localTipId == blockId(b1.header)

    let
      clientChain = Chain.init(genesis)
      server = newStandardSwitch()
      client = newStandardSwitch()
    let clientSyncer = Syncer.init(client, clientChain, testChainSyncProtocol)

    await server.start()
    await client.start()
    try:
      await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)
      var raised = false
      try:
        await initialBlockDownload(clientSyncer, @[server.peerInfo.peerId])
      except IBDFailure:
        raised = true
      check raised
    finally:
      await client.stop()
      await server.stop()

  asyncTest "initialBlockDownload succeeds when peer chain is taller and download sends blocks":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    var serverChain = Chain.init(genesis)
    check serverChain.localTree.addBlockToTree(b1)
    let b1id = blockId(b1.header)
    check serverChain.localTree.localTipId == b1id

    let
      clientChain = Chain.init(genesis)
      server = newStandardSwitch()
    let serverSyncer = Syncer.init(server, serverChain, testChainSyncProtocol)
    mountCryptarchiaSyncHandler(serverSyncer)
    let client = newStandardSwitch()
    let clientSyncer = Syncer.init(client, clientChain, testChainSyncProtocol)

    await server.start()
    await client.start()
    try:
      await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)
      await initialBlockDownload(clientSyncer, @[server.peerInfo.peerId])
      check clientChain.localTree.hasBlock(b1id)
      check clientChain.localTree.localTipId == b1id
    finally:
      await client.stop()
      await server.stop()

suite "LBP2PNode cryptarchia IBD at startup":
  asyncTest "bootstrap peer serves chain; client syncs 1-block taller tip on start()":
    await runLbp2pIbdSyncTest(1, 5033.Port, 5034.Port)

  asyncTest "client syncs 10-block bootstrap chain on start()":
    await runLbp2pIbdSyncTest(10, 5040.Port, 5041.Port)

  asyncTest "client syncs 50-block bootstrap chain on start()":
    await runLbp2pIbdSyncTest(50, 5050.Port, 5051.Port)

  asyncTest "client syncs 100-block bootstrap chain on start()":
    await runLbp2pIbdSyncTest(100, 5060.Port, 5061.Port)

{.pop.}
