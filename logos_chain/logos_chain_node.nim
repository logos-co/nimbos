# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  system/ansi_c,
  std/os,
  chronicles,
  metrics,
  stew/byteutils,
  ./node,
  ./api/server,
  "./core/block/genesis",
  ./[buildinfo, binary_common, process_state]

from libp2p/crypto/ed25519/ed25519 import EdPublicKeySize, toBytes
from "./core/block/types" import blockId

when defined(windows):
  from ./winservice import establishWindowsService

logScope: topics = "logos_nd"

proc doRunLBNode(
    config: var LBNodeConf, rng: ref HmacDrbgContext
) {.raises: [CatchableError].} =
  let deploymentSettings = loadDeploymentSettings(config.deploymentSettingsFile).valueOr:
    fatal "Invalid deployment-settings file", err = error
    quit QuitFailure

  let genesisBlock = createGenesisBlock(deploymentSettings.cryptarchia.genesisState)
  let genesisBlockId = blockId(genesisBlock.header)
  var leaderKeyBytes: array[EdPublicKeySize, byte]
  let leaderKeyWritten = toBytes(genesisBlock.header.proofOfLeadership.leaderKey, leaderKeyBytes)
  doAssert leaderKeyWritten == EdPublicKeySize, "failed to encode genesis PoL leader key"
  info "Constructed genesis block from deployment settings",
    genesisBlockId = byteutils.toHex(genesisBlockId),
    bedrockVersion = genesisBlock.header.bedrockVersion,
    slot = genesisBlock.header.slot,
    parentBlock = byteutils.toHex(genesisBlock.header.parentBlock),
    blockRoot = byteutils.toHex(genesisBlock.header.blockRoot),
    txCount = genesisBlock.txs.len,
    opCount = deploymentSettings.cryptarchia.genesisState.tx.ops.len,
    proofCount = deploymentSettings.cryptarchia.genesisState.opProofs.len,
    executionGasPrice = deploymentSettings.cryptarchia.genesisState.tx.executionGasPrice,
    storageGasPrice = deploymentSettings.cryptarchia.genesisState.tx.permanentStorageGasPrice,
    polLeaderVoucher = byteutils.toHex(genesisBlock.header.proofOfLeadership.leaderVoucher),
    polEntropyContribution = byteutils.toHex(genesisBlock.header.proofOfLeadership.entropyContribution),
    polProof = byteutils.toHex(genesisBlock.header.proofOfLeadership.proof),
    polLeaderKey = byteutils.toHex(leaderKeyBytes)

  info "Launching Logos node",
    version = fullVersionStr,
    cmdParams = commandLineParams(),
    config

  ProcessState.setupStopHandlers()

  # This should be in a data directory
  createPidFile("lb_node.pid")

  if ProcessState.stopIt(notice("Shutting down", reason = it)):
    return

  let
    taskpool = setupTaskpool(config.numThreads)
    node = waitFor(LBNode.init(rng, config, deploymentSettings)).valueOr:
      return

  # Nim GC metrics (for the main thread) will be collected in onSecond(), but
  # we disable piggy-backing on other metrics here.
  setSystemMetricsAutomaticUpdate(false)

  node.metricsServer = waitFor(config.initMetricsServer()).valueOr:
    return

  let
    restPort = 5050.Port
    restAllowedOrigin = none(string)
    restServer = RestServerRef.init(
      defaultAdminListenAddress, restPort, restAllowedOrigin,
      validateBeaconApiQueries, nimbusAgentStr, config)

  restServer.router.installNodeApiHandlers(node)
  restServer.start()

  try:
    node.run(nil)
  finally:
    waitFor restServer.stop()

proc handleStartUpCmd(config: var LBNodeConf) {.raises: [CatchableError].} =
  let rng = HmacDrbgContext.new()
  doRunLBNode(config, rng)

# noinline to keep it in stack traces
proc main*() {.noinline, raises: [CatchableError].} =
  const copyright =
    "Copyright (c) 2026-" & compileYear & " Status Research & Development GmbH"

  var config = LBNodeConf.loadWithBanners(clientId, copyright, [""]).valueOr:
    writePanicLine error # Logging not yet set up
    quit QuitFailure

  setupLogging(config.logLevel, config.logStdout, config.logFile)
  setupFileLimits()

  ## This Ctrl+C handler exits the program in non-graceful way.
  ## In a regular Logos node run, it will be overwritten later with a
  ## different handler performing a graceful exit.
  proc exitImmediatelyOnCtrlC() {.noconv.} =
    # No allocations in signal handler
    cstdout.rawWrite("Shutting down after having received SIGINT / ctrl-c")
    quit QuitSuccess
  setControlCHook(exitImmediatelyOnCtrlC)

  # equivalent SIGTERM handler
  when declared(ansi_c.SIGTERM):
    proc exitImmediatelyOnSIGTERM(signal: cint) {.noconv.} =
      # No allocations in signal handler
      cstdout.rawWrite("Shutting down after having received SIGTERM")
      quit QuitSuccess
    c_signal(ansi_c.SIGTERM, exitImmediatelyOnSIGTERM)

  when defined(windows):
    if config.runAsService:
      proc exitService() =
        ProcessState.scheduleStop("exitService")
      establishWindowsService(clientId, copyright, [""],
                              "logos_chain_node", LBNodeConf,
                              handleStartUpCmd, exitService)
    else:
      handleStartUpCmd(config)
  else:
    handleStartUpCmd(config)

when isMainModule:
  main()

{.pop.}
