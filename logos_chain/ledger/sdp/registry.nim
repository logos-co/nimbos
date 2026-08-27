# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [Service Declaration Protocol v1.3.0](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-service-declaration-protocol.md)

{.push raises: [], gcsafe.}

import
  std/tables,
  results,
  ./blend_rewards,
  ./state as sdpState,
  ../../deployment/deployment_settings as deploy

export blend_rewards, sdpState

type
  SdpSnapshots* = Table[ServiceType, Table[EpochNumber, SdpState]]
    ## Frozen SDP state keyed by **target epoch** ``n`` (``S_n`` for use during
    ## epoch ``n``). Keys ``0`` and ``1`` are both set to the genesis snapshot.
    ## For ``n >= 2``, taken when epoch ``n-2`` starts; snapshot ``S_n`` is
    ## pruned at the start of epoch ``n+1``.

  SdpParams* = object
    parameters*: Table[ServiceType, ServiceParameters]
    stakeThresholds*: seq[sdpState.MinStake]
    rewardsParams*: BlendRewardsParams

  SdpRegistry* = object
    state*: SdpState
    snapshots*: SdpSnapshots
    params*: SdpParams
    blendRewards*: BlendRewards
    lastEpochStarted*: Opt[EpochNumber]
      ## Highest epoch for which epoch-boundary processing has run.
      ## ``none`` until the first boundary.

func validateInactivityPeriod(params: ServiceParameters) =
  doAssert params.inactivityPeriod >= SnapshotFinalizationDelay,
    "inactivity_period must be >= 2 epochs"

func blendRewardsParams*(
    settings: deploy.DeploymentSettings, slotsPerEpoch: uint64
): BlendRewardsParams =
  ## Reward parameters from the deployment settings; rounds per epoch equals
  ## slots per epoch since the round duration is the slot duration.
  BlendRewardsParams(
    roundsPerEpoch: slotsPerEpoch,
    messageFrequencyPerRound:
      settings.blend.core.scheduler.cover.messageFrequencyPerRound,
    numBlendLayers: uint64(settings.blend.common.numBlendLayers),
    dataReplicationFactor: uint64(settings.blend.common.dataReplicationFactor),
    minimumNetworkSize: uint64(settings.blend.common.minimumNetworkSize),
    activityThresholdSensitivity:
      uint64(settings.blend.core.activityThresholdSensitivity))

func init*(
    T: type SdpRegistry,
    sdpConfig: deploy.SdpConfig,
    rewardsParams: BlendRewardsParams,
): T =
  let bnParams = ServiceParameters(
    inactivityPeriod: sdpConfig.bn.inactivityPeriod,
    epoch: sdpConfig.bn.epoch,
  )
  validateInactivityPeriod(bnParams)
  validateBlendRewardsParams(rewardsParams)
  T(
    state: SdpState.init(),
    snapshots: SdpSnapshots(),
    params: SdpParams(
      parameters: [(ServiceType.bn, bnParams)].toTable(),
      stakeThresholds: @[sdpState.MinStake(
        stakeThreshold: sdpConfig.minStake.threshold.uint64,
        epoch: sdpConfig.minStake.epoch,
      )],
      rewardsParams: rewardsParams,
    ),
    lastEpochStarted: Opt.none(EpochNumber),
  )

func onEpochStarted*(
    registry: sink SdpRegistry,
    epoch: EpochNumber,
): SdpRegistry =
  ## Runs withdrawal finalization and epoch snapshotting at an epoch boundary;
  ## ``epoch`` must advance past ``lastEpochStarted``.
  # The registry is fork-local (copied with LedgerState per branch), so a
  # reorg never needs to rewind lastEpochStarted; callers gate on epoch
  # advancement, making a stale epoch a logic error.
  doAssert registry.lastEpochStarted.isNone or epoch > registry.lastEpochStarted.get(),
    "onEpochStarted: epoch must advance past lastEpochStarted"
  if epoch == 0:
    var genesisSnap = registry.snapshots.mgetOrPut(
      ServiceType.bn, Table[EpochNumber, SdpState](),
    )
    genesisSnap[0] = registry.state
    genesisSnap[1] = registry.state
    registry.snapshots[ServiceType.bn] = genesisSnap
    registry.lastEpochStarted = Opt.some(EpochNumber(0))
    return registry
  let prev = registry.lastEpochStarted.valueOr(EpochNumber(0))
  for service, params in registry.params.parameters.pairs:
    if params.epoch > epoch:
      continue
    var byEpoch = registry.snapshots.mgetOrPut(
      service, Table[EpochNumber, SdpState](),
    )
    # Spec citation: "At the start of epoch n, each node takes a snapshot of the SDP registry
    # at the last block from the finalized epoch. ... Changes to the declaration registry
    # take effect with up to a two-epoch delay: messages sent during epoch n are included in
    # the next snapshot (for epoch n+2)." (https://github.com/logos-co/logos-lips/blob/d064449307d28a76b3555dc7b5064d15ee19d7f5/docs/blockchain/raw/bedrock-service-declaration-protocol.md#snapshots)
    #
    # No state changes (like finalizeWithdrawals) should occur before the snapshot is taken.
    # Since onEpochStarted is called at the start of epoch `epoch`, registry.state represents
    # the finalized state of the end of `epoch - 1`. We map this to target epoch `epoch + 1`
    # so that target epoch `T` reads the state finalized at the end of `T - 2`.
    # A blockless span ran no boundaries; backfill its snapshot keys.
    # Nothing changed in between, so each one is the boundary state.
    for target in max(prev + SnapshotFinalizationDelay, epoch) .. epoch + 1:
      byEpoch[target] = registry.state
    # A boundary at epoch E leaves keys {E, E+1}, so only the previous
    # pair can have ended; del ignores absent keys.
    for target in [prev, prev + 1]:
      if target < epoch:
        byEpoch.del(target)
    registry.snapshots[service] = byEpoch
  registry.state = finalizeWithdrawals(registry.state, epoch)
  registry.lastEpochStarted = Opt.some(epoch)
  registry


func getEpochSnapshot*(
    snapshots: SdpSnapshots,
    service: ServiceType,
    epochNumber: EpochNumber,
): Opt[SdpState] =
  # One lookup per level; the outer copy is shallow, the states inside are
  # persistent structures.
  var byEpoch = snapshots.getOrDefault(service)
  byEpoch.withValue(epochNumber, state):
    return Opt.some(state[])
  Opt.none(SdpState)

func getParametersAt*(
    registry: SdpRegistry,
    service: ServiceType,
    epoch: EpochNumber,
): Opt[ServiceParameters] =
  if service notin registry.params.parameters:
    return Opt.none(ServiceParameters)
  let params = registry.params.parameters.getOrDefault(service)
  if params.epoch <= epoch:
    Opt.some(params)
  else:
    Opt.none(ServiceParameters)

func notWithdrawnAt(info: DeclarationInfo, epoch: EpochNumber): bool =
  ## Whether no scheduled withdrawal has taken effect by ``epoch``.
  # `slotToEpoch` reaches `high(EpochNumber)`, so that value cannot stand in
  # for "no withdrawal".
  let withdrawAt = info.withdrawAt.valueOr:
    return true
  epoch < withdrawAt

func isActiveAt(
    info: DeclarationInfo, epoch: EpochNumber, params: ServiceParameters
): bool =
  ## Active at ``epoch``: activity seen within the inactivity period, and no
  ## withdrawal in effect. A fresh declaration counts from its first snapshot.
  # The operator sets `inactivity_period`, and the spec bounds it from below
  # only. Adding it to an epoch can wrap, so compare the distance instead.
  let lastActive = info.active.valueOr(info.created + SnapshotFinalizationDelay)
  (epoch <= lastActive or epoch - lastActive <= params.inactivityPeriod) and
    info.notWithdrawnAt(epoch)

func activeBlendProviders*(
    registry: SdpRegistry, targetEpoch: EpochNumber
): seq[tuple[providerId: ProviderId, zkId: ZkPublicKey]] =
  ## Blend provider set for ``targetEpoch``: the epoch snapshot's
  ## declarations, filtered to the ones active at that epoch.
  # Service parameters that are absent or not yet in force leave no way to
  # judge activity, so the set is empty rather than filtered with defaults.
  let
    snapshot = getEpochSnapshot(
      registry.snapshots, ServiceType.bn, targetEpoch).valueOr:
      return @[]
    params = getParametersAt(registry, ServiceType.bn, targetEpoch).valueOr:
      return @[]
  var providers: seq[tuple[providerId: ProviderId, zkId: ZkPublicKey]]
  for info in snapshot.declarations.values:
    if info.service == ServiceType.bn and
        isActiveAt(info, targetEpoch, params):
      providers.add (providerId: info.providerId, zkId: info.zkId)
  providers

func appendParameters*(
    registry: var SdpRegistry,
    service: ServiceType,
    params: ServiceParameters,
) =
  validateInactivityPeriod(params)
  registry.params.parameters[service] = params

func appendMinStake*(
    registry: var SdpRegistry,
    entry: sdpState.MinStake,
) =
  registry.params.stakeThresholds.add(entry)

func getMinStakeAt*(
    registry: SdpRegistry,
    epoch: EpochNumber,
): Opt[sdpState.MinStake] =
  var best = Opt.none(sdpState.MinStake)
  for entry in registry.params.stakeThresholds:
    if entry.epoch <= epoch:
      if best.isNone or entry.epoch >= best.get().epoch:
        best = Opt.some(entry)
  best

{.pop.}
