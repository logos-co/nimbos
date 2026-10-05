# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/times,
  chronos/unittest2/asynctests,
  libp2p/switch,
  libp2p/protocols/pubsub/gossipsub,
  ../../testutil,
  ./helpers,
  ../../../logos_chain/sync/[types, syncer],
  ../../../logos_chain/node

proc initGatingTestLBNode(
    network: LBP2PNode,
    genesis: Block,
    proposalTopic: string = "",
    syncer: Syncer = nil,
    genesisTime: uint64 = uint64(max(getTime().toUnix() - 500, 0'i64)),
): LBNode =
  var ds = DeploymentSettings(
    time: TimeDeploymentSettings(slotDuration: chronos.seconds(1))
  )
  if proposalTopic.len > 0:
    ds.cryptarchia.gossipsubProtocol = proposalTopic
  let bp = BlockProcessor.new(initTestChain(genesis, genesisTime = genesisTime))
  bp.start()
  LBNode(
    network: network,
    config: LBNodeConf(),
    deploymentSettings: ds,
    processor: bp,
    syncer: syncer,
    shutdownEvent: newAsyncEvent(),
  )

suite "sync/syncer":
  test "isSynced returns false when syncer or processor is nil":
    var nilSyncer: Syncer = nil
    check not nilSyncer.isSynced()

  test "isSynced returns false before syncer is started (ibdFut is nil)":
    let genesis = createGenesisBlock(SignedMantleTx(testGenesisTx())).get
    let chain = initTestChain(genesis)
    let bp = BlockProcessor.new(chain)
    let syncer = Syncer.init(nil, bp, testChainSyncProtocol)

    check syncer.ibdFut == nil
    check not syncer.isSynced()

  test "isSynced returns false while IBD future is running and returns true once completed":
    let genesis = createGenesisBlock(SignedMantleTx(testGenesisTx())).get
    let chain = initTestChain(genesis)
    let bp = BlockProcessor.new(chain)
    let syncer = Syncer.init(nil, bp, testChainSyncProtocol)

    # Simulate running IBD future
    let runningFut = Future[void].Raising([CancelledError]).init("simulated_ibd")
    syncer.ibdFut = runningFut

    check not syncer.isSynced()

    # Once IBD future completes, isSynced returns true
    runningFut.complete()
    check syncer.ibdFut.completed
    check syncer.isSynced()

  asyncTest "GossipSub proposal validator ignores proposals while node is syncing, accepts once synced":
    const topic = "/logos-blockchain/cryptarchia/1.0.0"
    let peers = await createBootstrapPeers()
    let
      genesis = createGenesisBlock(SignedMantleTx(testGenesisTx())).get
      gid = blockId(genesis.header)

    # 1. Create listener node with a syncer in running IBD state
    let
      genesisTime = uint64(max(getTime().toUnix() - 2, 0'i64))
      listenerChain = initTestChain(genesis, genesisTime = genesisTime)
      listenerBp = BlockProcessor.new(listenerChain)
    listenerBp.start()

    let
      listenerSyncer = Syncer.init(peers.listener.switch, listenerBp, testChainSyncProtocol)
      ibdSimFut = Future[void].Raising([CancelledError]).init("ibd_sim")
    listenerSyncer.ibdFut = ibdSimFut

    var ds = DeploymentSettings(
      time: TimeDeploymentSettings(slotDuration: chronos.seconds(1))
    )
    ds.cryptarchia.gossipsubProtocol = topic

    let listenerNode = LBNode(
      network: peers.listener,
      config: LBNodeConf(),
      deploymentSettings: ds,
      processor: listenerBp,
      syncer: nil,
      shutdownEvent: newAsyncEvent(),
    )

    let dialerNode = initGatingTestLBNode(
      peers.dialer, genesis, proposalTopic = topic, genesisTime = genesisTime
    )

    try:
      await listenerNode.initializeNetworking()
      await dialerNode.initializeNetworking()
      listenerNode.syncer = listenerSyncer

      check waitUntil(peers.dialer.switch.isConnected(peers.listenerPeerId))

      # Node is currently syncing (IBD running)
      check not listenerSyncer.isSynced()

      let b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      let id1 = blockId(b1.header)
      let p1 = Proposal(header: b1.header, references: default(References), signature: b1.signature)

      # 2. Broadcast proposal while listener is syncing -> validator ignores it (fast drop)
      check waitUntil((await peers.dialer.broadcast(topic, p1)).isOk)
      # Wait brief moment for gossip propagation
      await sleepAsync(chronos.milliseconds(50))

      # Listener ignored p1: not in localTree, not in orphanPool
      check not listenerNode.processor.localTree.hasBlock(id1)
      check listenerChain.orphanPool.len == 0

      # 3. Simulate IBD catching up: listener applies b1 via sync stream, then completes IBD
      check (await listenerBp.addBlock(BlockSource.Sync, b1, id1)).isOk
      check listenerNode.processor.localTree.hasBlock(id1)
      check listenerNode.processor.localTree.localTipId == id1

      ibdSimFut.complete()
      check listenerSyncer.isSynced()

      # 4. Create and broadcast proposal p2 (child of b1) now that node is Synced -> validator accepts and applies it
      let b2 = childBlock(b1.header, id1, SlotNumber(2), [])
      let id2 = blockId(b2.header)
      let p2 = Proposal(header: b2.header, references: default(References), signature: b2.signature)

      check waitUntil((await peers.dialer.broadcast(topic, p2)).isOk)
      check waitUntil(listenerNode.processor.localTree.hasBlock(id2))
      check listenerNode.processor.localTree.localTipId == id2
    finally:
      await dialerNode.processor.stop()
      await listenerNode.processor.stop()
      await peers.dialer.stop()
      await peers.listener.stop()

{.pop.}
