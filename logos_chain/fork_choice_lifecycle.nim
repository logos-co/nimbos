# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [Cryptarchia Bootstrapping & Synchronization v1.0.2](https://github.com/logos-co/logos-lips/blob/663ae35d59d834784dd086cc5f14ec35e8dbecf5/docs/blockchain/raw/cryptarchia-v1-bootstr-sync.md)

{.push raises: [], gcsafe.}

import
  chronicles,
  chronos,
  results,
  stew/byteutils,
  ./consensus/consensus_state,
  ./consensus/clock,
  ./chain/block_processor,
  ./node_state

logScope:
  topics = "fork_choice_lifecycle"

type
  LifecyclePhase {.pure.} = enum
    InitialBlockDownload
    ProlongedBootstrap
    Online

  StartupForkChoiceReason {.pure.} = enum
    ExplicitFlag
    LibAtGenesis
    NoSavedState
    OfflineTooLong
    ClockSkew
    WithinGrace

  ForkChoiceLifecycle* = ref object
    processor: BlockProcessor
    dataDir: string
    phase: LifecyclePhase
    prolongedBootstrapDuration: chronos.Duration
    prolongedBootFut: Future[void].Raising([CancelledError])
    heartbeatFut: Future[void].Raising([CancelledError])

const
  ProlongedBootstrapDuration = 24.hours
    ## Spec: T_boot = 24h prolonged bootstrap period before transitioning to Online fork choice.
  OfflineGracePeriodDuration* = 20.minutes
    ## Spec: T_offline = 20m offline grace period to restart without switching to Bootstrap rule.
  HeartbeatInterval = chronos.minutes(1)

# https://github.com/logos-co/logos-lips/blob/663ae35d59d834784dd086cc5f14ec35e8dbecf5/docs/blockchain/raw/cryptarchia-v1-bootstr-sync.md#setting-the-fork-choice-rule
func determineStartupForkChoiceRule(
    explicitBootstrapFlag: bool,
    isLibAtGenesis: bool,
    lastOnlineTimestampUnix: Opt[uint64],
    currentTimestampUnix: uint64,
): tuple[rule: ForkChoiceRule, reason: StartupForkChoiceReason] =
  ## Determines initial ForkChoiceRule upon node startup according to the specification:
  ## 1. Explicit --bootstrap flag -> Bootstrap
  ## 2. LIB at Genesis -> Bootstrap
  ## 3. Missing last online timestamp -> Bootstrap
  ## 4. Offline duration > T_offline (20 minutes) -> Bootstrap
  ## 5. Backwards clock skew (currentTimestampUnix < lastOnline) -> Online (per spec)
  ## 6. Restart within grace period -> Online
  if explicitBootstrapFlag:
    return (ForkChoiceRule.Bootstrap, StartupForkChoiceReason.ExplicitFlag)
  if isLibAtGenesis:
    return (ForkChoiceRule.Bootstrap, StartupForkChoiceReason.LibAtGenesis)
  let lastOnline = lastOnlineTimestampUnix.valueOr:
    return (ForkChoiceRule.Bootstrap, StartupForkChoiceReason.NoSavedState)
  if currentTimestampUnix < lastOnline:
    return (ForkChoiceRule.Online, StartupForkChoiceReason.ClockSkew)
  if currentTimestampUnix - lastOnline > uint64(OfflineGracePeriodDuration.seconds):
    return (ForkChoiceRule.Bootstrap, StartupForkChoiceReason.OfflineTooLong)
  (ForkChoiceRule.Online, StartupForkChoiceReason.WithinGrace)

func inspectSavedState(
    savedState: Opt[NodeStateRecord], consensus: ConsensusState
): tuple[lastOnline: Opt[uint64], effectiveLib: BlockId] =
  # Until persistent block/tree storage is loaded on startup, `consensus` starts at genesis,
  # so `hasBlock` is false for any non-genesis saved LIB and safely forces Bootstrap on restart.
  let state = savedState.valueOr:
    return (Opt.none(uint64), consensus.genesisId)
  let lib =
    if state.libBlockId == consensus.genesisId or
        not consensus.hasBlock(state.libBlockId):
      consensus.genesisId
    else:
      state.libBlockId
  (Opt.some(state.lastOnlineTimestampUnix), lib)

proc initLifecycle(
    processor: BlockProcessor,
    dataDir: string,
    explicitBootstrap: bool,
    prolongedBootstrapDuration: chronos.Duration,
): ForkChoiceLifecycle =
  let
    savedState = loadNodeState(dataDir)
    nowUnix = nowWallclockSeconds()
    (lastOnlineOpt, effectiveLib) = inspectSavedState(savedState, processor.consensus)
    (startupRule, startupReason) = determineStartupForkChoiceRule(
      explicitBootstrapFlag = explicitBootstrap,
      isLibAtGenesis = effectiveLib == processor.consensus.genesisId,
      lastOnlineTimestampUnix = lastOnlineOpt,
      currentTimestampUnix = nowUnix,
    )

  if startupReason == StartupForkChoiceReason.ClockSkew:
    warn "Clock skew detected; saved node state timestamp is in the future",
      nowUnix = nowUnix,
      savedLastOnlineUnix = lastOnlineOpt.valueOr(0'u64)

  info "Determined startup fork choice rule",
    rule = $startupRule,
    explicitBootstrap = explicitBootstrap,
    hasSavedState = savedState.isSome,
    effectiveLib = toHex(effectiveLib),
    reason = $startupReason

  if startupRule == ForkChoiceRule.Online:
    processor.switchToOnline()

  ForkChoiceLifecycle(
    processor: processor,
    dataDir: dataDir,
    phase: LifecyclePhase.InitialBlockDownload,
    prolongedBootstrapDuration: prolongedBootstrapDuration,
  )

proc init*(
    _: type ForkChoiceLifecycle,
    processor: BlockProcessor,
    dataDir: string,
    explicitBootstrap = false,
    prolongedBootstrapDuration = ProlongedBootstrapDuration,
): ForkChoiceLifecycle =
  initLifecycle(processor, dataDir, explicitBootstrap, prolongedBootstrapDuration)

func canProposeBlocks*(self: ForkChoiceLifecycle): bool =
  ## Spec: [Cryptarchia Bootstrapping & Synchronization - Proposing New Blocks]
  ## A node can start proposing blocks only after the Prolonged Bootstrap Period is complete.
  self.phase == LifecyclePhase.Online

proc persist(self: ForkChoiceLifecycle) =
  if self.phase == LifecyclePhase.Online:
    let
      nowUnix = nowWallclockSeconds()
      libId = self.processor.consensus.latestImmutable.id
    saveNodeState(self.dataDir, nowUnix, libId).isOkOr:
      warn "Failed to persist node state", error

proc switchToOnline(self: ForkChoiceLifecycle) =
  notice "Switching to Online fork choice rule"
  self.phase = LifecyclePhase.Online
  self.processor.switchToOnline()
  self.persist()

proc runProlongedBootstrap(self: ForkChoiceLifecycle): Future[void] {.async: (raises: [CancelledError]).} =
  debug "Fork choice lifecycle entered prolonged bootstrap period",
    duration = self.prolongedBootstrapDuration
  try:
    await chronos.sleepAsync(self.prolongedBootstrapDuration)
    notice "Prolonged bootstrap period completed; switching to Online fork choice rule"
    self.switchToOnline()
  finally:
    self.prolongedBootFut = nil

proc onIbdComplete*(self: ForkChoiceLifecycle) =
  if self.phase != LifecyclePhase.InitialBlockDownload:
    return
  case self.processor.consensus.forkChoiceRule
  of ForkChoiceRule.Online:
    self.phase = LifecyclePhase.Online
    self.persist()
  of ForkChoiceRule.Bootstrap:
    if self.prolongedBootstrapDuration <= chronos.ZeroDuration:
      debug "Skipping prolonged bootstrap period; switching immediately to Online fork choice rule"
      self.switchToOnline()
    else:
      self.phase = LifecyclePhase.ProlongedBootstrap
      self.prolongedBootFut = self.runProlongedBootstrap()

proc runHeartbeat(self: ForkChoiceLifecycle): Future[void] {.async: (raises: [CancelledError]).} =
  # TODO: Offline-without-stop (system sleep / suspend) will be managed in a follow-up PR.
  while true:
    self.persist()
    await chronos.sleepAsync(HeartbeatInterval)

proc start*(self: ForkChoiceLifecycle) =
  doAssert self.heartbeatFut == nil, "fork choice lifecycle already started"
  self.heartbeatFut = self.runHeartbeat()

proc stop*(self: ForkChoiceLifecycle) {.async: (raises: []).} =
  var futs: seq[FutureBase]
  if self.prolongedBootFut != nil:
    futs.add(self.prolongedBootFut)
    self.prolongedBootFut = nil
  if self.heartbeatFut != nil:
    futs.add(self.heartbeatFut)
    self.heartbeatFut = nil
  await cancelAndWait(futs)
  self.persist()

{.pop.}
