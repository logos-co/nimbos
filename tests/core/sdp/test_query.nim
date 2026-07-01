# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  results,
  ../../../logos_chain/core/mantle/[operations, utxo],
  ./test_helpers,
  ./test_utxo_helpers

import ../../../logos_chain/core/sdp/query

func seedQueryRegistry(): SdpRegistry =
  var registry = testSdpRegistry()
  appendParameters(registry, ServiceType.bn, ServiceParameters(
    sessionLength: 10, lockPeriod: 1,
    inactivityPeriod: 1, retentionPeriod: 1, timestamp: 0,
  ), TestSecurityParam)
  appendMinStake(registry, MinStake(stakeThreshold: 200, timestamp: 50))
  registry

suite "core/sdp/query":
  test "timestamp queries use the event index and reject unfinalized heights":
    var registry = seedQueryRegistry()
    let utxo = mkUtxo(value = 200, pkSeed = 1)
    let declaration = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: mkProvider(1),
      lockedNoteId: utxo.id,
      zkId: utxo.note.zkPublicKey,
    )
    let declId = installTestDeclaration(registry, declaration, 10)

    check getAllProviderId(registry, finalizedHeight = 20, 21).isErr
    check getAllProviderId(registry, finalizedHeight = 20, 21).error == UnfinalizedTimestamp

    let providers = getAllProviderId(registry, finalizedHeight = 20, 10).get()
    check providers.len == 1
    check providers[0] == declaration.providerId

    let infos = getAllDeclarationInfo(registry, finalizedHeight = 20, 10).get()
    check infos.len == 1
    check infos[0].created == 10'u64

    check getDeclarationInfo(registry, finalizedHeight = 20, declId).get().providerId == declaration.providerId
    check getDeclarationInfo(registry, declaration.providerId).isOk

  test "getAllProviderIdSince spans events up to finalized height":
    var registry = seedQueryRegistry()
    let utxo = mkUtxo(value = 200, pkSeed = 2)
    let declaration = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: mkProvider(2),
      lockedNoteId: utxo.id,
      zkId: utxo.note.zkPublicKey,
    )
    let declId = installTestDeclaration(registry, declaration, 10)
    let active = ActiveMessage(declarationId: declId, nonce: 1, metadata: @[])
    installTestActive(registry, active, 15)

    check getAllProviderIdSince(registry, finalizedHeight = 20, 12).get().len == 1
    check getAllDeclarationInfoSince(registry, finalizedHeight = 20, 12).get().len == 1
    check getAllProviderIdSince(registry, finalizedHeight = 20, 16).get().len == 0

  test "getDeclarationInfo returns RetentionExpired after garbage collection":
    var registry = seedQueryRegistry()
    let utxo = mkUtxo(value = 200, pkSeed = 3)
    let declaration = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: mkProvider(3),
      lockedNoteId: utxo.id,
      zkId: utxo.note.zkPublicKey,
    )
    let declId = installTestDeclaration(registry, declaration, 10)
    collectGarbage(registry.state, registry.params.parameters, 31)

    check getDeclarationInfo(registry, finalizedHeight = 31, declId).error == RetentionExpired
    check getAllDeclarationInfo(registry, finalizedHeight = 31, 10).error == RetentionExpired

  test "service parameters and min stake queries":
    let registry = seedQueryRegistry()

    check getServiceParameters(
      registry, ServiceType.bn, finalizedHeight = 100, 100,
    ).get().sessionLength == 10'u64
    check getAllServiceParameters(registry, finalizedHeight = 100, 100).get().len == 1
    check getAllServiceParametersSince(registry, finalizedHeight = 100, 0).get().len == 1

    check getMinStake(registry, finalizedHeight = 100, 25).get().stakeThreshold == 100'u64
    check getMinStake(registry, finalizedHeight = 100, 75).get().stakeThreshold == 200'u64
    check getMinStakeSince(registry, finalizedHeight = 100, 50).get().len == 1

{.pop.}
