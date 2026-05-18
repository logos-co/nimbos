# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [].}
{.used.}

import std/options
import chronos
import chronos/unittest2/asynctests
import unittest2

import libp2p/builders

import "../../../logos_chain/bedrock/block"/[block_types, genesis]
import "../../../logos_chain/bedrock/local_tree"
import "../../../logos_chain/sync"/[config, types, initial_block_download]
import ./helpers

from "../../../logos_chain/bedrock/mantle/primitives" import SlotNumber

# ---------------------------------------------------------------------------
# Download blocks
# ---------------------------------------------------------------------------

suite "sync/initial_block_download (download blocks)":
  test "decodeBlocksFromDownloadResponses roundtrip (genesis wrapped in dbrBlock)":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let blksOpt = decodeBlocksFromDownloadResponses(@[
      DownloadBlocksResponse(kind: dbrBlock, downloadedBlock: try:
        serializeBlockToSeq(genesis, cryptarchiaSyncBincodeConfig)
      except CatchableError:
        @[])
    ])
    check blksOpt.isSome and blksOpt.unsafeGet.len == 1
    check blockId(blksOpt.unsafeGet[0].header) == blockId(genesis.header)

  test "collectBlocksForDownloadRequest returns blocks from known tip to target":
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
    let blocks = collectBlocksForDownloadRequest(tree, req)
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

{.pop.}
