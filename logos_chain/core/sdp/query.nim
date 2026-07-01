# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP ledger query helpers (finalized state only).
## Spec: [1.0.0 Service Declaration Protocol](https://nomos-tech.notion.site/1-0-0-Service-Declaration-Protocol-1fd261aa09df819ca9f8eb2bdfd4ec1d)

{.push raises: [], gcsafe.}

import
  results,
  std/[sequtils, tables],
  ./[registry, state]

export registry, state

const allEventTypes = [EventType.created, EventType.active, EventType.withdrawn]

type
  SdpQueryError* {.pure.} = enum
    UnfinalizedTimestamp
    NotFound
    RetentionExpired

func validateFinalizedTimestamp*(
    finalizedHeight, timestamp: BlockNumber,
): Result[void, SdpQueryError] =
  if timestamp > finalizedHeight:
    return err(UnfinalizedTimestamp)
  ok()

func declarationWasIndexed*(
    events: Table[EventType, Table[ServiceType, Table[BlockNumber, seq[DeclarationId]]]],
    declId: DeclarationId, upTo: BlockNumber,
): bool =
  allEventTypes.anyIt:
    let byService = events.getOrDefault(it)
    toSeq(byService.keys).anyIt:
      toSeq(byService.getOrDefault(it).pairs).anyIt:
        it[0] <= upTo and declId in it[1]

func declarationIdsInTimestampRange(
    byTimestamp: Table[BlockNumber, seq[DeclarationId]],
    fromTimestamp, toTimestamp: BlockNumber,
): seq[DeclarationId] =
  concat mapIt(
    filterIt(toSeq(byTimestamp.pairs), it[0] >= fromTimestamp and it[0] <= toTimestamp),
    it[1],
  )

func collectEventDeclarationIdsAt*(
    registry: SdpRegistry,
    timestamp: BlockNumber,
): seq[DeclarationId] =
  var ids: seq[DeclarationId] = @[]
  for eventType in allEventTypes.filterIt(it in registry.index.events):
    let byService = registry.index.events.getOrDefault(eventType)
    for service in byService.keys:
      ids.add getEventDeclarations(registry, eventType, service, timestamp)
  deduplicate ids

func collectEventDeclarationIdsSince*(
    events: Table[EventType, Table[ServiceType, Table[BlockNumber, seq[DeclarationId]]]],
    fromTimestamp, toTimestamp: BlockNumber,
): seq[DeclarationId] =
  var ids: seq[DeclarationId] = @[]
  for eventType in allEventTypes.filterIt(it in events):
    let byService = events.getOrDefault(eventType)
    for service in byService.keys:
      ids.add declarationIdsInTimestampRange(
        byService.getOrDefault(service), fromTimestamp, toTimestamp,
      )
  deduplicate ids

func loadDeclarationForQuery*(
    registry: SdpRegistry,
    finalizedHeight: BlockNumber,
    declId: DeclarationId,
): Result[DeclarationInfo, SdpQueryError] =
  let infoOpt = getDeclaration(registry.state, declId)
  if infoOpt.isSome:
    return ok(infoOpt.get())
  if declarationWasIndexed(registry.index.events, declId, finalizedHeight):
    return err(RetentionExpired)
  err(NotFound)

func loadDeclarationsForQuery(
    registry: SdpRegistry,
    finalizedHeight: BlockNumber,
    declIds: openArray[DeclarationId],
): Result[seq[DeclarationInfo], SdpQueryError] =
  var entries = newSeqOfCap[DeclarationInfo](declIds.len)
  for declId in declIds:
    entries.add(?loadDeclarationForQuery(registry, finalizedHeight, declId))
  ok(entries)

func declarationInfoAt(
    registry: SdpRegistry,
    finalizedHeight, timestamp: BlockNumber,
): Result[seq[DeclarationInfo], SdpQueryError] =
  ?validateFinalizedTimestamp(finalizedHeight, timestamp)
  loadDeclarationsForQuery(
    registry, finalizedHeight, collectEventDeclarationIdsAt(registry, timestamp),
  )

func declarationInfoSince(
    registry: SdpRegistry,
    finalizedHeight, timestamp: BlockNumber,
): Result[seq[DeclarationInfo], SdpQueryError] =
  ?validateFinalizedTimestamp(finalizedHeight, timestamp)
  loadDeclarationsForQuery(
    registry, finalizedHeight,
    collectEventDeclarationIdsSince(
      registry.index.events, timestamp, finalizedHeight,
    ),
  )

func getAllProviderId*(
    registry: SdpRegistry,
    finalizedHeight, timestamp: BlockNumber,
): Result[seq[ProviderId], SdpQueryError] =
  let infos = ?declarationInfoAt(registry, finalizedHeight, timestamp)
  ok mapIt(infos, it.providerId)

func getAllProviderIdSince*(
    registry: SdpRegistry,
    finalizedHeight, timestamp: BlockNumber,
): Result[seq[ProviderId], SdpQueryError] =
  let infos = ?declarationInfoSince(registry, finalizedHeight, timestamp)
  ok mapIt(infos, it.providerId)

func getAllDeclarationInfo*(
    registry: SdpRegistry,
    finalizedHeight, timestamp: BlockNumber,
): Result[seq[DeclarationInfo], SdpQueryError] =
  declarationInfoAt(registry, finalizedHeight, timestamp)

func getAllDeclarationInfoSince*(
    registry: SdpRegistry,
    finalizedHeight, timestamp: BlockNumber,
): Result[seq[DeclarationInfo], SdpQueryError] =
  declarationInfoSince(registry, finalizedHeight, timestamp)

func getDeclarationInfo*(
    registry: SdpRegistry, providerId: ProviderId,
): Result[DeclarationInfo, SdpQueryError] =
  let matches = filterIt(
    toSeq(registry.state.declarations.values), it.providerId == providerId,
  )
  if matches.len == 0:
    return err(NotFound)
  let activeIdx = matches.findIt(it.withdrawn == 0)
  if activeIdx >= 0:
    ok(matches[activeIdx])
  else:
    ok(matches[0])

func getDeclarationInfo*(
    registry: SdpRegistry,
    finalizedHeight: BlockNumber,
    declId: DeclarationId,
): Result[DeclarationInfo, SdpQueryError] =
  loadDeclarationForQuery(registry, finalizedHeight, declId)

func getAllServiceParameters*(
    registry: SdpRegistry,
    finalizedHeight, timestamp: BlockNumber,
): Result[seq[(ServiceType, ServiceParameters)], SdpQueryError] =
  ?validateFinalizedTimestamp(finalizedHeight, timestamp)
  ok filterIt(toSeq(registry.params.parameters.pairs), it[1].timestamp <= timestamp)

func getAllServiceParametersSince*(
    registry: SdpRegistry,
    finalizedHeight, timestamp: BlockNumber,
): Result[seq[(ServiceType, ServiceParameters)], SdpQueryError] =
  ?validateFinalizedTimestamp(finalizedHeight, timestamp)
  ok filterIt(toSeq(registry.params.parameters.pairs), it[1].timestamp >= timestamp)

func getServiceParameters*(
    registry: SdpRegistry,
    service: ServiceType,
    finalizedHeight, timestamp: BlockNumber,
): Result[ServiceParameters, SdpQueryError] =
  ?validateFinalizedTimestamp(finalizedHeight, timestamp)
  if service notin registry.params.parameters:
    return err(NotFound)
  let params = registry.params.parameters.getOrDefault(service)
  if params.timestamp <= timestamp:
    ok(params)
  else:
    err(NotFound)

func getMinStake*(
    registry: SdpRegistry,
    finalizedHeight, timestamp: BlockNumber,
): Result[MinStake, SdpQueryError] =
  ?validateFinalizedTimestamp(finalizedHeight, timestamp)
  let stake = getMinStakeAt(registry, timestamp).valueOr:
    return err(NotFound)
  ok(stake)

func getMinStakeSince*(
    registry: SdpRegistry,
    finalizedHeight, timestamp: BlockNumber,
): Result[seq[MinStake], SdpQueryError] =
  ?validateFinalizedTimestamp(finalizedHeight, timestamp)
  ok filterIt(registry.params.stakeThresholds, it.timestamp >= timestamp)

{.pop.}
