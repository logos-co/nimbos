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
  ./node,
  ./api/server,
  ./deployment/deployment_settings,
  ./[buildinfo, binary_common, process_state]

when defined(windows):
  from ./winservice import establishWindowsService

logScope: topics = "logos_nd"

proc doRunLBNode(
    config: var LBNodeConf, rng: ref HmacDrbgContext
) {.raises: [CatchableError].} =
  let deploymentSettings = loadDeploymentSettings(config.deploymentSettingsFile).valueOr:
    fatal "Invalid deployment-settings file", err = error
    quit QuitFailure

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
    node = waitFor(LBNode.init(rng, config, deploymentSettings, chain.genesisBlock)).valueOr:
      return

  # Nim GC metrics (for the main thread) will be collected in onSecond(), but
  # we disable piggy-backing on other metrics here.
  setSystemMetricsAutomaticUpdate(false)

  node.metricsServer = waitFor(config.initMetricsServer()).valueOr:
    return

  let
    restAllowedOrigin = none(string)
    restServer = RestServerRef.init(
      defaultAdminListenAddress, config.restPort, restAllowedOrigin,
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
