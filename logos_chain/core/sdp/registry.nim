# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [1.0.0 Service Declaration Protocol](https://nomos-tech.notion.site/1-0-0-Service-Declaration-Protocol-1fd261aa09df819ca9f8eb2bdfd4ec1d)

{.push raises: [], gcsafe.}

import
  results,
  std/tables,
  ./state,
  ./types as sdpTypes,
  ../../deployment/deployment_settings as deploy

export state

type
  SdpIndex* = object
    events*: Table[EventType, Table[ServiceType, Table[BlockNumber, seq[DeclarationId]]]]
    sessions*: Table[ServiceType, Table[uint64, SdpState]]

  SdpParams* = object
    parameters*: Table[ServiceType, ServiceParameters]
    stakeThresholds*: seq[sdpTypes.MinStake]

  SdpRegistry* = object
    state*: SdpState
    index*: SdpIndex
    params*: SdpParams

func validateSessionLength*(params: ServiceParameters, securityParam: uint64) =
  ## ``session_length`` must be at least ``k`` (security param).
  doAssert params.sessionLength > 0, "session_length must be > 0"
  doAssert params.sessionLength >= securityParam,
    "session_length must be >= consensus finality parameter k"

func init*(
    T: type SdpRegistry,
    sdpConfig: deploy.SdpConfig,
    securityParam: uint64,
): T =
  let bnDefaults = defaultBnServiceParameters(sdpConfig.bn.epoch.uint64)
  let bnParams = ServiceParameters(
    sessionLength: bnDefaults.sessionLength,
    lockPeriod: sdpConfig.bn.lockPeriod.uint64,
    inactivityPeriod: sdpConfig.bn.inactivityPeriod.uint64,
    retentionPeriod: sdpConfig.bn.retentionPeriod.uint64,
    timestamp: sdpConfig.bn.epoch.uint64,
  )
  validateSessionLength(bnParams, securityParam)
  T(
    state: SdpState.init(),
    index: SdpIndex(),
    params: SdpParams(
      parameters: [(ServiceType.bn, bnParams)].toTable(),
      stakeThresholds: @[sdpTypes.MinStake(
        stakeThreshold: sdpConfig.minStake.threshold.uint64,
        timestamp: sdpConfig.minStake.timestamp.uint64,
      )],
    ),
  )

func onBlockApplied*(
    registry: var SdpRegistry,
    previousBlockNumber: BlockNumber,
    blockNumber: BlockNumber,
) =
  registry.state = collectGarbage(
    registry.state, registry.params.parameters, blockNumber,
  )
  for service, params in registry.params.parameters.pairs:
    if params.timestamp > blockNumber:
      continue
    let
      prevSession = previousBlockNumber div params.sessionLength
      curSession = blockNumber div params.sessionLength
    if curSession <= prevSession or curSession < 2:
      continue
    var bySession = registry.index.sessions.mgetOrPut(
      service, Table[uint64, SdpState](),
    )
    bySession[curSession] = registry.state

func getSessionSnapshot*(
    snapshots: Table[ServiceType, Table[uint64, SdpState]],
    service: ServiceType,
    sessionNumber: uint64,
): Opt[SdpState] =
  if service notin snapshots:
    return Opt.none(SdpState)
  let
    bySession = snapshots.getOrDefault(service)
    storedSession = if sessionNumber < 2: 0'u64 else: sessionNumber
  if storedSession in bySession:
    Opt.some(bySession.getOrDefault(storedSession))
  else:
    Opt.none(SdpState)

func appendParameters*(
    registry: var SdpRegistry,
    service: ServiceType,
    params: ServiceParameters,
    securityParam: uint64,
) =
  validateSessionLength(params, securityParam)
  registry.params.parameters[service] = params

func getParametersAt*(
    registry: SdpRegistry,
    service: ServiceType,
    timestamp: BlockNumber,
): Opt[ServiceParameters] =
  if service notin registry.params.parameters:
    return Opt.none(ServiceParameters)
  let params = registry.params.parameters.getOrDefault(service)
  if params.timestamp <= timestamp:
    Opt.some(params)
  else:
    Opt.none(ServiceParameters)

func appendMinStake*(
    registry: var SdpRegistry,
    entry: sdpTypes.MinStake,
) =
  registry.params.stakeThresholds.add(entry)

func getMinStakeAt*(
    registry: SdpRegistry,
    timestamp: BlockNumber,
): Opt[sdpTypes.MinStake] =
  var best = Opt.none(sdpTypes.MinStake)
  for entry in registry.params.stakeThresholds:
    if entry.timestamp <= timestamp:
      if best.isNone or entry.timestamp >= best.get().timestamp:
        best = Opt.some(entry)
  best

func indexEvent*(
    registry: var SdpRegistry,
    eventType: EventType,
    service: ServiceType,
    timestamp: BlockNumber,
    declarationId: DeclarationId,
) =
  registry.index.events.mgetOrPut(
    eventType, Table[ServiceType, Table[BlockNumber, seq[DeclarationId]]](),
  ).mgetOrPut(
    service, Table[BlockNumber, seq[DeclarationId]](),
  ).mgetOrPut(timestamp, @[]).add(declarationId)

func getEventDeclarations*(
    registry: SdpRegistry,
    eventType: EventType,
    service: ServiceType,
    timestamp: BlockNumber,
): seq[DeclarationId] =
  registry.index.events.getOrDefault(eventType).getOrDefault(service).getOrDefault(timestamp)

{.pop.}
