# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [1.1.0 Service Declaration Protocol](https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/bedrock-service-declaration-protocol.md)

{.push raises: [], gcsafe.}

import
  results,
  std/tables,
  ./state as sdpState,
  ../../deployment/deployment_settings as deploy

export sdpState

type
  SdpSnapshots* = Table[ServiceType, Table[EpochNumber, SdpState]]
    ## Frozen SDP state keyed by **target epoch** ``n`` (``S_n`` for use during
    ## epoch ``n``). Keys ``0`` and ``1`` are both set to the genesis snapshot.
    ## For ``n >= 2``, taken when epoch ``n-2`` starts; snapshot ``S_n`` is
    ## pruned at the start of epoch ``n+1``.

  SdpParams* = object
    parameters*: Table[ServiceType, ServiceParameters]
    stakeThresholds*: seq[sdpState.MinStake]

  SdpRegistry* = object
    state*: SdpState
    snapshots*: SdpSnapshots
    params*: SdpParams
    lastEpochStarted*: Opt[EpochNumber]
      ## Highest epoch for which epoch-boundary processing has run.
      ## ``none`` until the first boundary.
      ## TODO(EpochState): rewind on chain reorgs once epoch management lands.

func validateInactivityPeriod*(params: ServiceParameters) =
  doAssert params.inactivityPeriod >= 2,
    "inactivity_period must be >= 2 epochs"

func init*(
    T: type SdpRegistry,
    sdpConfig: deploy.SdpConfig,
): T =
  let bnParams = ServiceParameters(
    inactivityPeriod: sdpConfig.bn.inactivityPeriod.uint64,
    epoch: sdpConfig.bn.epoch.uint64,
  )
  validateInactivityPeriod(bnParams)
  T(
    state: SdpState.init(),
    snapshots: SdpSnapshots(),
    params: SdpParams(
      parameters: [(ServiceType.bn, bnParams)].toTable(),
      stakeThresholds: @[sdpState.MinStake(
        stakeThreshold: sdpConfig.minStake.threshold.uint64,
        epoch: sdpConfig.minStake.epoch.uint64,
      )],
    ),
    lastEpochStarted: Opt.none(EpochNumber),
  )

proc onEpochStarted*(
    registry: var SdpRegistry,
    epoch: EpochNumber,
) =
  ## Runs withdrawal finalization and epoch snapshotting at an epoch boundary.
  ## No-op when ``epoch`` is not greater than ``lastEpochStarted``.
  ## TODO(EpochState): callers must pass the consensus epoch; rewind
  ## ``lastEpochStarted`` on reorgs once epoch management lands.
  if registry.lastEpochStarted.isSome and epoch <= registry.lastEpochStarted.get():
    return
  if epoch == 0:
    var genesisSnap = registry.snapshots.mgetOrPut(
      ServiceType.bn, Table[EpochNumber, SdpState](),
    )
    genesisSnap[0] = registry.state
    genesisSnap[1] = registry.state
    registry.snapshots[ServiceType.bn] = genesisSnap
    registry.lastEpochStarted = Opt.some(0'u64)
    return
  let last = registry.lastEpochStarted
  registry.state = finalizeWithdrawals(registry.state, epoch)
  for service, params in registry.params.parameters.pairs:
    if params.epoch > epoch:
      continue
    var byEpoch = registry.snapshots.mgetOrPut(
      service, Table[EpochNumber, SdpState](),
    )
    byEpoch[epoch + 2] = registry.state
    # Drop S_n for target epochs lastEpochStarted .. epoch - 1.
    for target in last.get(0'u64) .. epoch - 1:
      if target in byEpoch:
        byEpoch.del(target)
    registry.snapshots[service] = byEpoch
  registry.lastEpochStarted = Opt.some(epoch)


func getEpochSnapshot*(
    snapshots: SdpSnapshots,
    service: ServiceType,
    epochNumber: EpochNumber,
): Opt[SdpState] =
  if service notin snapshots:
    return Opt.none(SdpState)
  let byEpoch = snapshots.getOrDefault(service)
  if epochNumber in byEpoch:
    Opt.some(byEpoch.getOrDefault(epochNumber))
  else:
    Opt.none(SdpState)

func appendParameters*(
    registry: var SdpRegistry,
    service: ServiceType,
    params: ServiceParameters,
) =
  validateInactivityPeriod(params)
  registry.params.parameters[service] = params

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
