# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/cpuinfo,
  chronos, chronicles, presto, presto/server,
  bearssl/rand,
  metrics, metrics/chronos_httpserver,
  stew/byteutils,
  ./chain/block_processor,
  ./[conf, process_state],
  ./core/[types, utils],
  ./deployment/deployment_settings,
  ./networking/network,
  ./sync/syncer,
  ./zk/[circuits, pol, poc, poq, prover, zksign]

from ./chain/proposal import reconstructAndValidateBlock, ProposalValidationError
from ./core/mantle/tx_validation import validateMantleTxStateless
from ./core/mantle/tx_types import SignedMantleTx, ValidSignedMantleTx
from ./core/types as coreTypes import Block, blockId, Proposal
from libp2p/crypto/ed25519/ed25519 import EdPublicKeySize, toBytes
from libp2p/peerid import PeerId
from libp2p/protocols/pubsub/pubsub import ValidationResult
from libp2p/protocols/pubsub/gossipsub import
  TopicParams, init

from std/random import randomize
from taskpools import Taskpool, new, shutdown

export
  chronos, presto, server, conf,
  deployment_settings, network, utils, block_processor

logScope: topics = "logos_nd"

type
  LBNode* = ref object
    network*: LBP2PNode
    netKeys*: NetKeyPair
    config*: LBNodeConf
    deploymentSettings*: DeploymentSettings
    processor*: BlockProcessor
    syncer*: Syncer
    metricsServer*: Opt[MetricsHttpServerRef]
    shutdownEvent*: AsyncEvent
    taskpool*: Taskpool
    prover*: Prover
      ## nil where the native prover libraries do not link (Windows).

template rng*(node: LBNode): ref HmacDrbgContext =
  node.network.rng

proc initFullNode(
    node: LBNode,
    rng: ref HmacDrbgContext,
) {.async: (raises: [CancelledError]).} =
  template config(): auto = node.config

  proc eventWaiter(): Future[void] {.async: (raises: [CancelledError]).} =
    await node.shutdownEvent.wait()
    ProcessState.scheduleStop("shutdownEvent")

  asyncSpawn eventWaiter()

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
  randomize(rng[].generate(int))

  let circuitsDir = string(config.circuitsDir)
  verifyCircuitsVersion(circuitsDir).isOkOr:
    fatal "logos-blockchain-circuits bundle check failed",
      dir = circuitsDir,
      expected = ExpectedCircuitsVersion,
      err = $error,
      hint = "Run scripts/setup-logos-blockchain-circuits.sh"
    return Opt.none(LBNode)

  pol.loadAndInitVk(circuitsDir).isOkOr:
    fatal "PoL verification key install failed",
      path = verificationKeyPath(circuitsDir, Circuit.Pol), err = $error
    return Opt.none(LBNode)

  zksign.loadAndInitVk(circuitsDir).isOkOr:
    fatal "ZkSig verification key install failed",
      path = verificationKeyPath(circuitsDir, Circuit.Signature), err = $error
    return Opt.none(LBNode)

  poc.loadAndInitVk(circuitsDir).isOkOr:
    fatal "PoC verification key install failed",
      path = verificationKeyPath(circuitsDir, Circuit.Poc), err = $error
    return Opt.none(LBNode)

  poq.loadAndInitVk(circuitsDir).isOkOr:
    fatal "PoQ verification key install failed",
      path = verificationKeyPath(circuitsDir, Circuit.Poq), err = $error
    return Opt.none(LBNode)

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
    networkConfig(config),
    rng.getRandomNetKeys(),
  ).valueOr:
    error "Failed to initialize node", err = error
    return Opt.none(LBNode)

  let processor = BlockProcessor.new(chain)
  var nodeSyncer: Syncer = nil
  if processor.localTree != nil and
      deploymentSettings.network.chainSyncProtocolName.len > 0:
    nodeSyncer = Syncer.init(
      network.switch, processor, deploymentSettings.network.chainSyncProtocolName)

  if nodeSyncer != nil:
    info "Syncer configured at node startup",
      chainSyncProtocol = deploymentSettings.network.chainSyncProtocolName,
      genesisBlockId = blockId(genesisBlock.header)
  else:
    debug "Syncer not configured at node startup",
      hasLocalTree = processor.localTree != nil,
      chainSyncProtocol = deploymentSettings.network.chainSyncProtocolName

  # Created last so every earlier failure path has nothing to release.
  let numThreads =
    if config.numThreads == ThreadCount(0):
      max(minThreadCount, min(countProcessors(), maxThreadCount))
    else:
      int(config.numThreads)
  var taskpool =
    try:
      Taskpool.new(numThreads = numThreads)
    except CatchableError as exc:
      fatal "Failed to create taskpool", err = exc.msg
      return Opt.none(LBNode)
  info "Threadpool started", numThreads

  let zkProver = Prover.new(circuitsDir, taskpool).valueOr:
    when defined(windows):
      warn "Proof generation unavailable on this platform; verification only",
        dir = circuitsDir, err = $error
      Prover(nil)
    else:
      fatal "Failed to initialize the Groth16 prover", dir = circuitsDir, err = $error
      taskpool.shutdown()
      return Opt.none(LBNode)

  ok LBNode(
    network: network,
    config: config,
    deploymentSettings: deploymentSettings,
    processor: processor,
    syncer: nodeSyncer,
    shutdownEvent: newAsyncEvent(),
    taskpool: taskpool,
    prover: zkProver)

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

func toValidationResult(err: BlockApplyError): ValidationResult =
  case err.kind
  of BlockApplyErrorKind.AlreadyApplied,
     BlockApplyErrorKind.FutureSlot,
     BlockApplyErrorKind.TreeRejected:
    ValidationResult.Ignore
  of BlockApplyErrorKind.InvalidStructure,
     BlockApplyErrorKind.LedgerRejected,
     BlockApplyErrorKind.StatelessTxRejected:
    ValidationResult.Reject

proc handleGossipProposal(
    node: LBNode, proposal: Proposal, src: PeerId
): Future[ValidationResult] {.async: (raises: [CancelledError]).} =
  trace "GossipSub handling received proposal",
    blockId = byteutils.toHex(blockId(proposal.header)),
    slot = proposal.header.slot,
    src = $src

  let blk = reconstructAndValidateBlock(
    proposal, node.processor.localTree, node.processor.ledger, node.processor.mempool
  ).valueOr:
    if error == ProposalValidationError.MissingReference:
      debug "GossipSub cannot reconstruct block from proposal: missing tx in mempool",
        blockId = byteutils.toHex(blockId(proposal.header)),
        error = $error,
        src = $src
      return ValidationResult.Ignore
    debug "GossipSub rejected invalid proposal",
      blockId = byteutils.toHex(blockId(proposal.header)),
      error = $error,
      src = $src
    return ValidationResult.Reject

  let applyRes = await node.processor.addBlock(BlockSource.Gossip, blk)
  if applyRes.isOk():
    debug "GossipSub accepted reconstructed block into local tree",
      blockId = byteutils.toHex(blockId(blk.header)),
      slot = blk.header.slot,
      src = $src
    ValidationResult.Accept
  else:
    trace "GossipSub handled block apply result",
      blockId = byteutils.toHex(blockId(blk.header)),
      err = applyRes.error.kind
    toValidationResult(applyRes.error)

proc handleGossipTx(node: LBNode, tx: SignedMantleTx, src: PeerId): ValidationResult =
  trace "GossipSub handling received tx",
    opCount = tx.tx.ops.len,
    src = $src

  if validateMantleTxStateless(tx).isErr:
    debug "GossipSub rejected invalid mantle tx", src = $src
    return ValidationResult.Reject

  let nowSlot = node.processor.currentWallclockSlot()
  discard node.processor.mempool.add(ValidSignedMantleTx(tx), nowSlot)

  ValidationResult.Accept

proc installMessageValidators(node: LBNode): seq[string] =
  var topics: seq[string]

  let blockTopic = node.deploymentSettings.cryptarchia.gossipsubProtocol
  if blockTopic.len > 0:
    node.network.addAsyncValidator(blockTopic) do (
        proposal: Proposal, src: PeerId
    ) -> Future[ValidationResult] {.async: (raises: [CancelledError]).} =
      await handleGossipProposal(node, proposal, src)
    topics.add(blockTopic)
  else:
    warn "Cryptarchia block gossipsub protocol topic is empty, validator not installed"

  let mempoolTopic = node.deploymentSettings.mempool.pubsubTopic
  if mempoolTopic.len > 0:
    node.network.addValidator(mempoolTopic) do (
        tx: SignedMantleTx, src: PeerId
    ) -> ValidationResult:
      handleGossipTx(node, tx, src)
    topics.add(mempoolTopic)
  else:
    warn "Mempool pubsub topic is empty, validator not installed"

  topics

proc stop(node: LBNode) =
  # The IBD task may be awaiting a queued result. Cancel it before the
  # processor cancels that future, so the cancellation comes from its owner.
  if node.syncer != nil:
    waitFor node.syncer.stop()
  waitFor node.processor.stop()
  try:
    waitFor node.network.stop()
  except CancelledError as exc:
    warn "Couldn't stop network", msg = exc.msg

  waitFor node.metricsServer.stopMetricsServer()

  # Drain in-flight tasks before the prover frees the buffers they read.
  node.taskpool.shutdown()
  if node.prover != nil:
    node.prover.close()

proc initializeNetworking*(node: LBNode) {.async.} =
  let topics = node.installMessageValidators()
  for topic in topics:
    node.network.subscribe(topic, TopicParams.init())
    debug "Subscribed to gossip topic", topic = topic

  info "Listening to incoming network requests"
  await node.network.startListening()

  await node.network.start()
  if node.syncer != nil:
    if node.network.bootstrapPeerIds.len > 0:
      debug "Waiting for bootstrap peer readiness before starting syncer",
        timeout = node.network.bootstrapTimeout
      let syncPeers = await node.network.waitForBootstrapPeers()
      if syncPeers.len == 0:
        fatal "Initial block download failed: no configured bootstrap peer reached within timeout",
          timeout = node.network.bootstrapTimeout
        ProcessState.scheduleStop("Bootstrap peer connection timeout")
        return
      node.syncer.start(
        Opt.some(proc(): seq[PeerId] = node.network.connectedBootstrapPeerIds())
      )
    else:
      node.syncer.start()

type StopFuture = Future[void].Raising([CancelledError])

proc run*(node: LBNode, stopper: StopFuture) {.raises: [CatchableError].} =
  ## Caller is responsible for installing REST handlers and starting the
  ## REST server before calling `run`.
  node.processor.start()
  waitFor node.initializeNetworking()

  ProcessState.notifyRunning()
  if ProcessState.stopIt(notice("Shutting down during startup", reason = it)):
    node.stop()
    return

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
