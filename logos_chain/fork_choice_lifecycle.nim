# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [Cryptarchia Bootstrapping & Synchronization](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/cryptarchia-v1-bootstr-sync.md)

{.push raises: [], gcsafe.}

import
  chronicles,
  chronos,
  results,
  ./consensus/consensus_state,
  ./consensus/clock,
  ./chain/block_processor,
  ./node_state

logScope:
  topics = "fork_choice_lifecycle"

type
  StartupForkChoiceReason* {.pure.} = enum
    ExplicitFlag
    LibAtGenesis
    NoSavedState
    OfflineTooLong
    ClockSkew
    WithinGrace

  ForkChoiceLifecycle* = ref object
    processor: BlockProcessor
    dataDir: string
    prolongedBootstrapDuration: chronos.Duration
    prolongedBootFut: Future[void].Raising([CancelledError])
    heartbeatFut: Future[void].Raising([CancelledError])

const
  ProlongedBootstrapDuration* = 24.hours
    ## Spec: T_boot = 24h prolonged bootstrap period before transitioning to Online fork choice.
  OfflineGracePeriodDuration* = 20.minutes
    ## Spec: T_offline = 20m offline grace period to restart without switching to Bootstrap rule.
  HeartbeatInterval = chronos.minutes(1)

# https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/cryptarchia-v1-bootstr-sync.md#setting-the-fork-choice-rule
func determineStartupForkChoiceRule*(
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

func new*(
    _: type ForkChoiceLifecycle,
    processor: BlockProcessor,
    dataDir: string,
    prolongedBootstrapDuration = ProlongedBootstrapDuration,
): ForkChoiceLifecycle =
  ForkChoiceLifecycle(
    processor: processor,
    dataDir: dataDir,
    prolongedBootstrapDuration: prolongedBootstrapDuration,
  )

func canProposeBlocks*(self: ForkChoiceLifecycle): bool =
  ## Spec: [Cryptarchia Bootstrapping & Synchronization - Proposing New Blocks]
  ## A node can start proposing blocks only after the Prolonged Bootstrap Period is complete.
  ## In other words, the node should not propose blocks before switching to the Online fork choice rule.
  self.processor.consensus.forkChoiceRule == ForkChoiceRule.Online

proc persist(self: ForkChoiceLifecycle) =
  if self.processor.consensus.forkChoiceRule == ForkChoiceRule.Online:
    let
      nowUnix = nowWallclockSeconds()
      libId = self.processor.consensus.latestImmutableId
    saveNodeState(self.dataDir, nowUnix, libId).isOkOr:
      warn "Failed to persist node state", error

proc switchToOnline(self: ForkChoiceLifecycle) =
  if self.processor.consensus.forkChoiceRule != ForkChoiceRule.Online:
    notice "Switching to Online fork choice rule"
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

proc onSyncComplete*(self: ForkChoiceLifecycle) =
  if self.processor.consensus.forkChoiceRule == ForkChoiceRule.Online:
    return
  if self.prolongedBootFut != nil and not self.prolongedBootFut.finished():
    return
  if self.prolongedBootstrapDuration <= chronos.ZeroDuration:
    debug "Skipping prolonged bootstrap period; switching immediately to Online fork choice rule"
    self.switchToOnline()
    return
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
  if self.heartbeatFut != nil:
    await self.heartbeatFut.cancelAndWait()
    self.heartbeatFut = nil
  if self.prolongedBootFut != nil:
    await self.prolongedBootFut.cancelAndWait()
    self.prolongedBootFut = nil
  self.persist()

{.pop.}
