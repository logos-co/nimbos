# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[osproc, random],
  chronos, chronicles, presto, presto/server, bearssl/rand,
  metrics, metrics/chronos_httpserver,
  eth/p2p/discoveryv5/random2,
  stew/byteutils,
  ./chain/chain,
  ./[conf, process_state],
  ./core/[types, utils],
  ./deployment/deployment_settings,
  ./networking/network,
  ./sync/syncer,
  ./zk/[circuits, pol, zksign]

from ./core/types as coreTypes import Block, blockId
from libp2p/crypto/ed25519/ed25519 import EdPublicKeySize, toBytes
from libp2p/protocols/pubsub/gossipsub import
  TopicParams, init

export
  osproc, chronos, presto, server, conf,
  deployment_settings, network, utils, chain

logScope: topics = "logos_nd"

type
  LBNode* = ref object
    network*: LBP2PNode
    netKeys*: NetKeyPair
    config*: LBNodeConf
    deploymentSettings*: DeploymentSettings
    syncer*: Syncer
    metricsServer*: Opt[MetricsHttpServerRef]
    shutdownEvent*: AsyncEvent

template rng*(node: LBNode): ref HmacDrbgContext =
  node.network.rng

# Install a single circuit's VK or fatal-log and bail. Requires `circuitsDir`
# in scope at the call site and an enclosing proc returning `Opt[LBNode]`.
template loadVkOrFatal(circuit, pathFn: untyped, name: string) =
  circuit.loadAndInitVk(circuitsDir).isOkOr:
    fatal name & " verification key install failed",
      path = pathFn(circuitsDir), err = $error
    return Opt.none(LBNode)

proc initFullNode(
    node: LBNode,
    rng: ref HmacDrbgContext,
) {.async: (raises: [CancelledError]).} =
  template config(): auto = node.config

  proc eventWaiter(): Future[void] {.async: (raises: [CancelledError]).} =
    await node.shutdownEvent.wait()
    ProcessState.scheduleStop("shutdownEvent")

  asyncSpawn eventWaiter()

  node.network.registerProtocol(PeerSync, PeerSync.NetworkState.init())

proc init*(
    T: type LBNode,
    rng: ref HmacDrbgContext,
    config: LBNodeConf,
    deploymentSettings: DeploymentSettings,
): Future[Opt[LBNode]] {.async: (raises: [CancelledError]).} =
  var config = config

  if ProcessState.stopIt(notice("Shutting down", reason = it)):
    return Opt.none(LBNode)

  # Doesn't use std/random directly, but dependencies might
  randomize(rng[].rand(high(int)))

  let circuitsDir = string(config.circuitsDir)
  verifyCircuitsVersion(circuitsDir).isOkOr:
    fatal "logos-blockchain-circuits bundle check failed",
      dir = circuitsDir,
      expected = ExpectedCircuitsVersion,
      err = $error,
      hint = "Run scripts/setup-logos-blockchain-circuits.sh"
    return Opt.none(LBNode)

  loadVkOrFatal(pol, polVerificationKeyPath, "PoL")
  loadVkOrFatal(zksign, zksignVerificationKeyPath, "ZkSig")

  let chain = Chain.init(deploymentSettings).valueOr:
    fatal "Failed to initialize chain", err = error
    return Opt.none(LBNode)

  let genesisBlock = chain.genesisBlock
  block:
    let genesisState = genesisBlock.txs[0]
    var leaderKeyBytes: array[EdPublicKeySize, byte]
    let leaderKeyWritten = toBytes(
      genesisBlock.header.proofOfLeadership.leaderKey, leaderKeyBytes)
    doAssert leaderKeyWritten == EdPublicKeySize,
      "failed to encode genesis PoL leader key"
    info "Initialized chain from deployment settings",
      genesisBlockId = byteutils.toHex(blockId(genesisBlock.header)),
      bedrockVersion = genesisBlock.header.bedrockVersion,
      slot = genesisBlock.header.slot,
      parentBlock = byteutils.toHex(genesisBlock.header.parentBlock),
      blockRoot = byteutils.toHex(genesisBlock.header.blockRoot),
      txCount = genesisBlock.txs.len,
      opCount = genesisState.tx.ops.len,
      proofCount = genesisState.opProofs.len,
      polLeaderVoucher =
        byteutils.toHex(genesisBlock.header.proofOfLeadership.leaderVoucher),
      polEntropyContribution =
        byteutils.toHex(genesisBlock.header.proofOfLeadership.entropyContribution),
      polProof = byteutils.toHex(genesisBlock.header.proofOfLeadership.proof),
      polLeaderKey = byteutils.toHex(leaderKeyBytes),
      blockSignature = byteutils.toHex(genesisBlock.signature.data)

  let network = createLBP2PNode(
    rng,
    config,
    rng[].getRandomNetKeys(),
  ).valueOr:
    error "Failed to initialize node", err = error
    return Opt.none(LBNode)

  var nodeSyncer: Syncer = nil
  if chain.localTree != nil and deploymentSettings.network.chainSyncProtocolName.len > 0:
    nodeSyncer = Syncer.init(
      network.switch, chain, deploymentSettings.network.chainSyncProtocolName)

  if nodeSyncer != nil:
    info "Syncer configured at node startup",
      chainSyncProtocol = deploymentSettings.network.chainSyncProtocolName,
      genesisBlockId = blockId(genesisBlock.header)
  else:
    debug "Syncer not configured at node startup",
      hasLocalTree = chain.localTree != nil,
      chainSyncProtocol = deploymentSettings.network.chainSyncProtocolName

  ok LBNode(
    network: network,
    config: config,
    deploymentSettings: deploymentSettings,
    syncer: nodeSyncer,
    shutdownEvent: newAsyncEvent())

when defined(windows):
  from winservice import reportServiceStatusSuccess

proc onSlotStart(node: LBNode): Future[bool] {.async.} =
  when defined(windows):
    if node.config.runAsService:
      reportServiceStatusSuccess()

  false

proc runSlotLoop(node: LBNode) {.async.} =
  info "Scheduling first slot action"

  while true:
    # Start by waiting for the time when the slot starts. Sleeping relinquishes
    # control to other tasks which may or may not finish within the allotted
    # time, so below, we need to be wary that the ship might have sailed
    # already.
    await sleepAsync(chronos.seconds(1))

    let breakLoop = await onSlotStart(node)
    if breakLoop:
      break

proc onSecond(node: LBNode, time: Moment) =
  # Nim GC metrics (for the main thread)
  updateThreadMetrics()

proc runOnSecondLoop(node: LBNode) {.async.} =
  const
    sleepTime = chronos.seconds(1)
    nanosecondsIn1s = float(sleepTime.nanoseconds)
  while true:
    let start = chronos.now(chronos.Moment)
    await chronos.sleepAsync(sleepTime)
    let afterSleep = chronos.now(chronos.Moment)
    let sleepTime = afterSleep - start
    node.onSecond(start)
    let finished = chronos.now(chronos.Moment)
    let processingTime = finished - afterSleep
    trace "onSecond task completed", sleepTime, processingTime

func connectedPeersCount(node: LBNode): int =
  len(node.network.peerPool)

proc installMessageValidators(node: LBNode) =
  # Placeholder — real validators will be installed once gossip topics
  # and message types are defined for the Logos chain.
  discard

proc stop(node: LBNode) =
  try:
    waitFor node.network.stop()
  except CancelledError as exc:
    warn "Couldn't stop network", msg = exc.msg

  waitFor node.metricsServer.stopMetricsServer()

proc initializeNetworking(node: LBNode) {.async.} =
  node.installMessageValidators()

  info "Listening to incoming network requests"
  await node.network.startListening()

  await node.network.start()
  if node.syncer != nil:
    debug "Scheduling syncer startup after network bootstrap"
    node.syncer.start(node.network.bootstrapPeerIds)

type StopFuture = Future[void].Raising([CancelledError])

proc run*(node: LBNode, stopper: StopFuture) {.raises: [CatchableError].} =
  ## Caller is responsible for installing REST handlers and starting the
  ## REST server before calling `run`.
  waitFor node.initializeNetworking()

  ProcessState.notifyRunning()

  node.network.subscribe("/some/topic", TopicParams.init())

  asyncSpawn runSlotLoop(node)
  asyncSpawn runOnSecondLoop(node)

  while true:
    if (let reason = ProcessState.stopping(); reason.isSome()):
      notice "Shutting down", reason = reason[]
      break
    if stopper != nil and stopper.finished():
      break

    chronos.poll()

  # time to say goodbye
  node.stop()

{.pop.}
