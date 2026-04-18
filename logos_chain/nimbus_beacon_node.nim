# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  system/ansi_c,
  std/[os, random, strutils, times],
  chronos, chronicles,
  metrics, metrics/chronos_httpserver,
  eth/enr/enr,
  eth/p2p/discoveryv5/random2,
  ./rpc/rest_api,
  ./spec/datatypes/base,
  ./sync/sync_protocol,
  ./deployment_settings,
  ./[
    logos_chain_node, buildinfo,
    nimbus_binary_common, process_state]

from std/sequtils import filterIt, mapIt, toSeq
from libp2p/protocols/pubsub/errors import ValidationResult
from libp2p/protocols/pubsub/gossipsub import
  TopicParams, validateParameters, init

logScope: topics = "logos_nd"

proc initFullNode(
    node: LBNode,
    rng: ref HmacDrbgContext,
) {.async: (raises: [CancelledError]).} =
  template config(): auto = node.config

  proc isWithinWeakSubjectivityPeriod(): bool = true
  proc eventWaiter(): Future[void] {.async: (raises: [CancelledError]).} =
    await node.shutdownEvent.wait()
    ProcessState.scheduleStop("shutdownEvent")

  asyncSpawn eventWaiter()

  node.network.registerProtocol(PeerSync, PeerSync.NetworkState.init())

  node.network.registerProtocol(
    BeaconSync, default(BeaconSync.NetworkState))

proc init*(
    T: type LBNode,
    rng: ref HmacDrbgContext,
    config: LBNodeConf,
): Future[Opt[LBNode]] {.async: (raises: [CancelledError]).} =
  var config = config

  if ProcessState.stopIt(notice("Shutting down", reason = it)):
    return Opt.none(LBNode)

  # Doesn't use std/random directly, but dependencies might
  randomize(rng[].rand(high(int)))

  let restPort = 5050.Port
  const restAllowedOrigin = none(string)
  let restServer = RestServerRef.init(
    defaultAdminListenAddress, restPort, restAllowedOrigin,
    validateBeaconApiQueries, nimbusAgentStr, config)

  let
    network = createLBNode(
      rng,
      config,
      rng[].getRandomNetKeys(),
    ).valueOr:
      error "Failed to initialize node", err = error
      return Opt.none(LBNode)

  ok LBNode(
    network: network,
    config: config,
    restServer: restServer,
    shutdownEvent: newAsyncEvent())

func subnetLog(v: BitArray): string =
  $toSeq(v.oneIndices())

when defined(windows):
  from winservice import establishWindowsService, reportServiceStatusSuccess

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

proc installRestHandlers(restServer: RestServerRef, node: LBNode) =
  restServer.router.installNodeApiHandlers(node)

proc installMessageValidators(node: LBNode) =
  node.network.addValidator(
    "/some/topic", proc (
      signedBlock: AttestationData,
      src: PeerId,
    ): ValidationResult = ValidationResult.Accept)

proc stop(node: LBNode) =
  try:
    waitFor node.network.stop()
  except CatchableError as exc:
    warn "Couldn't stop network", msg = exc.msg

  waitFor node.metricsServer.stopMetricsServer()

proc initializeNetworking(node: LBNode) {.async.} =
  node.installMessageValidators()

  info "Listening to incoming network requests"
  await node.network.startListening()

  await node.network.start()

type StopFuture = Future[void].Raising([CancelledError])

proc run*(node: LBNode, stopper: StopFuture) {.raises: [CatchableError].} =
  waitFor node.initializeNetworking()

  ProcessState.notifyRunning()

  if not isNil(node.restServer):
    node.restServer.installRestHandlers(node)
    node.restServer.start()

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

proc doRunLBNode(
    config: var LBNodeConf, rng: ref HmacDrbgContext
) {.raises: [CatchableError].} =
  let depRes = mergeDeploymentSettingsFile(config)
  if depRes.isErr:
    fatal "Invalid deployment-settings file", err = depRes.error
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
    node = waitFor(LBNode.init(rng, config)).valueOr:
      return

  # Nim GC metrics (for the main thread) will be collected in onSecond(), but
  # we disable piggy-backing on other metrics here.
  setSystemMetricsAutomaticUpdate(false)

  node.metricsServer = waitFor(config.initMetricsServer()).valueOr:
    return

  node.run(nil)

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
  ## It's responsible for handling Ctrl+C in sub-commands such
  ## as `wallets *` and `deposits *`. In a regular Logos node
  ## run, it will be overwritten later with a different handler
  ## performing a graceful exit.
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
                              "nimbus_beacon_node", LBNodeConf,
                              handleStartUpCmd, exitService)
    else:
      handleStartUpCmd(config)
  else:
    handleStartUpCmd(config)

when isMainModule:
  main()

{.pop.}
