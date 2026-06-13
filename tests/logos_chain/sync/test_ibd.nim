# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import chronos
import chronos/unittest2/asynctests
import unittest2
import bincode

import libp2p/builders

import ../../../logos_chain/networking/network
import ../../../logos_chain/core/types
import ../../../logos_chain/chain/[genesis, chain]
import ../../../logos_chain/core/local_tree
import ../../../logos_chain/sync/[types, ibd_client, ibd_server, syncer]
import ./helpers
import ../../testutil

from ../../../logos_chain/core/mantle/primitives import SlotNumber

proc runLbp2pIbdSyncTest(
    extraBlocks: int, bootstrapPort, clientPort: Port,
) {.async.} =
  let
    sm = minimalSignedTx()
    genesis = createGenesisBlock(sm)

  var chainBootstrap = chain.init(genesis)
  let tipId = extendChainAfterGenesis(chainBootstrap.localTree, genesis, extraBlocks)
  check chainBootstrap.localTree.localTipId == tipId

  let chainClient = chain.init(genesis)

  let (confBootstrap, confClient, rngBootstrap, rngClient) =
    makeBootstrapConfs(bootstrapPort, clientPort)

  let bootstrapRes = createLBP2PNode(
    rngBootstrap,
    confBootstrap,
    rngBootstrap[].getRandomNetKeys(),
  )
  check bootstrapRes.isOk
  let bootstrap = bootstrapRes.get()
  let bootstrapSyncer = syncer.init(
    bootstrap.switch, chainBootstrap, testChainSyncProtocol)
  await bootstrap.startListening()
  bootstrapSyncer.start(@[])

  let
    bootstrapPeerId = bootstrap.switch.peerInfo.peerId
    bootstrapAddr =
      "/ip4/127.0.0.1/udp/" & $bootstrapPort &
      "/quic-v1/p2p/" & $bootstrapPeerId

  var confClientWithBootstrap = confClient
  confClientWithBootstrap.bootstrapNodes = @[bootstrapAddr]

  let clientRes = createLBP2PNode(
    rngClient,
    confClientWithBootstrap,
    rngClient[].getRandomNetKeys(),
  )
  check clientRes.isOk
  let
    client = clientRes.get()
    clientSyncer = syncer.init(client.switch, chainClient, testChainSyncProtocol)
    waitAttempts = 150 + extraBlocks * 5

  try:
    await client.start()
    clientSyncer.start(client.bootstrapPeerIds)

    check await waitLibp2pConnected(client.switch, bootstrapPeerId)
    check await waitLocalTreeBlock(chainClient.localTree, tipId, waitAttempts)
    check chainClient.localTree.localTipId == tipId
  finally:
    await client.stop()
    await bootstrap.stop()

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
    var serverChain = chain.init(genesis)
    check serverChain.localTree.addBlockToTree(b1)
    let
      b1id = blockId(b1.header)
      clientChain = chain.init(genesis)
      req = DownloadBlocksRequest(
        targetBlock: b1id, knownBlocks: buildKnownBlocks(clientChain.localTree))
      server = newStandardSwitch()
    let serverSyncer = syncer.init(server, serverChain, testChainSyncProtocol)
    mountCryptarchiaSyncHandler(serverSyncer)
    let client = newStandardSwitch()
    let clientSyncer = syncer.init(client, clientChain, testChainSyncProtocol)

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
    var serverChain = chain.init(genesis)
    let
      server = newStandardSwitch()
    let serverSyncer = syncer.init(server, serverChain, testChainSyncProtocol)
    mountCryptarchiaSyncHandler(serverSyncer)
    let client = newStandardSwitch()
    let clientSyncer = syncer.init(client, chain.init(genesis), testChainSyncProtocol)

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
    let clientSyncer = syncer.init(sw, chain.init(genesis), testChainSyncProtocol)
    await initialBlockDownload(clientSyncer, @[])

  asyncTest "initialBlockDownload succeeds when peer tip is already in local tree":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      server = newStandardSwitch()
    var serverChain = chain.init(genesis)
    var clientChain = chain.init(genesis)
    let serverSyncer = syncer.init(server, serverChain, testChainSyncProtocol)
    mountCryptarchiaSyncHandler(serverSyncer)
    let client = newStandardSwitch()
    let clientSyncer = syncer.init(client, clientChain, testChainSyncProtocol)

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
    var serverChain = chain.init(genesis)
    check serverChain.localTree.addBlockToTree(b1)
    check serverChain.localTree.localTipId == blockId(b1.header)

    let
      clientChain = chain.init(genesis)
      server = newStandardSwitch()
      client = newStandardSwitch()
    let clientSyncer = syncer.init(client, clientChain, testChainSyncProtocol)

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
    var serverChain = chain.init(genesis)
    check serverChain.localTree.addBlockToTree(b1)
    let b1id = blockId(b1.header)
    check serverChain.localTree.localTipId == b1id

    let
      clientChain = chain.init(genesis)
      server = newStandardSwitch()
    let serverSyncer = syncer.init(server, serverChain, testChainSyncProtocol)
    mountCryptarchiaSyncHandler(serverSyncer)
    let client = newStandardSwitch()
    let clientSyncer = syncer.init(client, clientChain, testChainSyncProtocol)

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
