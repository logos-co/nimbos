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
import ../../../logos_chain/chain/genesis
import ../../../logos_chain/core/local_tree
import ../../../logos_chain/sync/[types, initial_block_download]
import ./helpers
import ../../testutil

from ../../../logos_chain/core/mantle/primitives import SlotNumber

proc extendChainAfterGenesis(
    tree: LocalTree, genesis: Block, extraBlocks: int,
): BlockId =
  ## Add ``extraBlocks`` descendants on top of ``genesis``; return the tip id.
  let sm = minimalSignedTx()
  var parentHdr = genesis.header
  var parentId = blockId(genesis.header)
  for slot in 1 .. extraBlocks:
    let blk = childBlock(parentHdr, parentId, SlotNumber(slot.uint64), [sm])
    check tree.addBlockToTree(blk)
    parentHdr = blk.header
    parentId = blockId(blk.header)
  parentId

proc waitLocalTreeBlock(
    tree: LocalTree, id: BlockId, attempts: int = 150,
): Future[bool] {.async.} =
  for _ in 0 ..< attempts:
    if tree.hasBlock(id):
      return true
    await sleepAsync(100.milliseconds)
  false

proc runLbp2pIbdSyncTest(
    extraBlocks: int, bootstrapPort, clientPort: Port,
) {.async.} =
  let sm = minimalSignedTx()
  let genesis = createGenesisBlock(sm)

  let treeBootstrap = newLocalTree(genesis)
  let tipId = extendChainAfterGenesis(treeBootstrap, genesis, extraBlocks)
  check treeBootstrap.localTipId == tipId

  let treeClient = newLocalTree(genesis)

  let (confBootstrap, confClient, rngBootstrap, rngClient) =
    makeBootstrapConfs(bootstrapPort, clientPort)

  let bootstrapRes = createLBP2PNode(
    rngBootstrap,
    confBootstrap,
    rngBootstrap[].getRandomNetKeys(),
    treeBootstrap,
    testChainSyncProtocol,
  )
  check bootstrapRes.isOk
  let bootstrap = bootstrapRes.get()
  await bootstrap.startListening()

  let bootstrapPeerId = bootstrap.switch.peerInfo.peerId
  let bootstrapAddr =
    "/ip4/127.0.0.1/udp/" & $bootstrapPort &
    "/quic-v1/p2p/" & $bootstrapPeerId

  var confClientWithBootstrap = confClient
  confClientWithBootstrap.bootstrapNodes = @[bootstrapAddr]

  let clientRes = createLBP2PNode(
    rngClient,
    confClientWithBootstrap,
    rngClient[].getRandomNetKeys(),
    treeClient,
    testChainSyncProtocol,
  )
  check clientRes.isOk
  let client = clientRes.get()

  let waitAttempts = 150 + extraBlocks * 5

  try:
    await client.start()

    check await waitLibp2pConnected(client.switch, bootstrapPeerId)
    check await waitLocalTreeBlock(treeClient, tipId, waitAttempts)
    check treeClient.localTipId == tipId
  finally:
    await client.stop()
    await bootstrap.stop()

# ---------------------------------------------------------------------------
# Download blocks
# ---------------------------------------------------------------------------

suite "sync/initial_block_download (download blocks)":
  test "decodeBlocksFromDownloadResponses roundtrip (genesis wrapped in dbrBlock)":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let genesisWire = try:
      serializeBlockToSeq(genesis, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    let blksOpt = decodeBlocksFromDownloadResponses(@[
      DownloadBlocksResponse(kind: dbrBlock, downloadedBlock: genesisWire),
    ])
    check blksOpt.isSome and blksOpt.unsafeGet.len == 1
    check blockId(blksOpt.unsafeGet[0].header) == blockId(genesis.header)

  test "collectBlocksTargetToAncestor returns target block when path is one hop":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    let b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    check tree.addBlockToTree(b1)
    let b1id = blockId(b1.header)
    let req = DownloadBlocksRequest(
      targetBlock: b1id,
      knownBlocks: buildKnownBlocks(newLocalTree(genesis)),
    )
    let blocks = collectBlocksTargetToAncestor(tree, req)
    check blocks.len == 1
    check blockId(blocks[0].header) == b1id

  test "decodeBlocksFromDownloadResponses recovers blocks from handler-shaped response":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    let b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    check tree.addBlockToTree(b1)
    let req = DownloadBlocksRequest(
      targetBlock: blockId(b1.header),
      knownBlocks: buildKnownBlocks(newLocalTree(genesis)),
    )
    let msgs = downloadBlocksResponsesForRequest(tree, req)
    let blks = decodeBlocksFromDownloadResponses(msgs)
    check blks.isSome
    check blks.get.len == 1
    check blockId(blks.get[0].header) == blockId(b1.header)

  asyncTest "sendDownloadBlocksRequest round-trips over mounted sync handler":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let serverTree = newLocalTree(genesis)
    let b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    check serverTree.addBlockToTree(b1)
    let b1id = blockId(b1.header)

    let clientTree = newLocalTree(genesis)
    let req = DownloadBlocksRequest(
      targetBlock: b1id, knownBlocks: buildKnownBlocks(clientTree))

    let server = newStandardSwitch()
    mountCryptarchiaSyncHandler(server, serverTree, testChainSyncProtocol)
    let client = newStandardSwitch()

    await server.start()
    await client.start()
    try:
      await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)

      let respOpt = await sendDownloadBlocksRequest(
        client, server.peerInfo.peerId, req, testChainSyncProtocol)
      check respOpt.isSome
      let expected = downloadBlocksResponsesForRequest(serverTree, req)
      check downloadBlocksResponsesEqual(respOpt.get, expected)
      let blks = decodeBlocksFromDownloadResponses(respOpt.get)
      check blks.isSome
      check blks.get.len == 1
      check blockId(blks.get[0].header) == b1id
    finally:
      await client.stop()
      await server.stop()

# ---------------------------------------------------------------------------
# GetTip
# ---------------------------------------------------------------------------

suite "sync/initial_block_download (GetTip)":
  asyncTest "sendGetTipRequest round-trips over mounted sync handler":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let tree = newLocalTree(genesis)

    let server = newStandardSwitch()
    mountCryptarchiaSyncHandler(server, tree, testChainSyncProtocol)
    let client = newStandardSwitch()

    await server.start()
    await client.start()
    try:
      await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)

      let tipOpt = await sendGetTipRequest(client, server.peerInfo.peerId, testChainSyncProtocol)
      check tipOpt.isSome

      let expected = Tip(
        tip: localTipId(tree),
        slot: SlotNumber(0),
        height: tree.latestImmutableHeight,
      )
      check tipOpt.get.kind == gtrTip
      check tipOpt.get.tipData == expected
    finally:
      await client.stop()
      await server.stop()

# ---------------------------------------------------------------------------
# IBD: requester loop
# ---------------------------------------------------------------------------

suite "sync/initial_block_download (IBD requester loop)":
  asyncTest "initialBlockDownload with no peers completes without raising":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let tree = newLocalTree(genesis)
    let sw = newStandardSwitch()
    await initialBlockDownload(sw, @[], tree, testChainSyncProtocol)

  asyncTest "initialBlockDownload succeeds when peer tip is already in local tree":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let treeServer = newLocalTree(genesis)
    let treeClient = newLocalTree(genesis)

    let server = newStandardSwitch()
    mountCryptarchiaSyncHandler(server, treeServer, testChainSyncProtocol)
    let client = newStandardSwitch()

    await server.start()
    await client.start()
    try:
      await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)
      await initialBlockDownload(client, @[server.peerInfo.peerId], treeClient, testChainSyncProtocol)
    finally:
      await client.stop()
      await server.stop()

  asyncTest "initialBlockDownload raises when peer chain is taller but sync handler is not mounted":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let treeServer = newLocalTree(genesis)
    let b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    check treeServer.addBlockToTree(b1)
    check treeServer.localTipId == blockId(b1.header)

    let treeClient = newLocalTree(genesis)

    let server = newStandardSwitch()
    let client = newStandardSwitch()

    await server.start()
    await client.start()
    try:
      await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)
      var raised = false
      try:
        await initialBlockDownload(client, @[server.peerInfo.peerId], treeClient, testChainSyncProtocol)
      except IBDFailure:
        raised = true
      check raised
    finally:
      await client.stop()
      await server.stop()

  asyncTest "initialBlockDownload succeeds when peer chain is taller and download sends blocks":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let treeServer = newLocalTree(genesis)
    let b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    check treeServer.addBlockToTree(b1)
    let b1id = blockId(b1.header)
    check treeServer.localTipId == b1id

    let treeClient = newLocalTree(genesis)

    let server = newStandardSwitch()
    mountCryptarchiaSyncHandler(server, treeServer, testChainSyncProtocol)
    let client = newStandardSwitch()

    await server.start()
    await client.start()
    try:
      await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)
      await initialBlockDownload(client, @[server.peerInfo.peerId], treeClient, testChainSyncProtocol)
      check treeClient.hasBlock(b1id)
      check treeClient.localTipId == b1id
    finally:
      await client.stop()
      await server.stop()

# ---------------------------------------------------------------------------
# LBP2PNode IBD at startup
# ---------------------------------------------------------------------------

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
