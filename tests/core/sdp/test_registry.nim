# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[options, tables],
  unittest2,
  ../../../logos_chain/core/sdp/registry,
  ./test_helpers

suite "core/sdp/registry":
  test "stores service parameters per service":
    var registry = testSdpRegistry()
    check registry.params.parameters.len == 1
    check getParametersAt(registry, ServiceType.bn, 100).isSome

    appendParameters(registry, ServiceType.bn, ServiceParameters(
      sessionLength: 10, lockPeriod: 1, timestamp: 0,
    ), TestSecurityParam)
    check registry.params.parameters.len == 1
    check getParametersAt(registry, ServiceType.bn, 100).get().sessionLength == 10'u64

    appendParameters(registry, ServiceType.bn, ServiceParameters(
      sessionLength: 20, lockPeriod: 2, timestamp: 50,
    ), TestSecurityParam)
    check registry.params.parameters.len == 1
    check getParametersAt(registry, ServiceType.bn, 25).isNone
    check getParametersAt(registry, ServiceType.bn, 50).get().sessionLength == 20'u64

  test "stores versioned minimum stake entries":
    var registry = testSdpRegistry()
    check registry.params.stakeThresholds.len == 1
    check getMinStakeAt(registry, 100).isSome

    appendMinStake(registry, MinStake(stakeThreshold: 1000, timestamp: 0))
    appendMinStake(registry, MinStake(stakeThreshold: 2000, timestamp: 50))
    check registry.params.stakeThresholds.len == 3
    check getMinStakeAt(registry, 25).get().stakeThreshold == 1000'u64
    check getMinStakeAt(registry, 50).get().stakeThreshold == 2000'u64
    check getMinStakeAt(registry, 100).get().stakeThreshold == 2000'u64

  test "bundles state, index, and params":
    var registry = testSdpRegistry()
    check registry.state.declarations.len == 0
    check registry.index.sessions.len == 0
    check registry.params.parameters.len == 1
    check registry.params.stakeThresholds.len == 1

    appendParameters(registry, ServiceType.bn, ServiceParameters(
      sessionLength: 10, lockPeriod: 1, timestamp: 0,
    ), TestSecurityParam)
    onBlockApplied(registry, previousBlockNumber = 9, blockNumber = 10)
    check getSessionSnapshot(registry.index.sessions, ServiceType.bn, 2).isNone

  test "indexes declarations by type, service, and timestamp":
    var registry = testSdpRegistry()
    var declA, declB: DeclarationId
    declA[0] = 1
    declB[0] = 2

    indexEvent(registry, EventType.created, ServiceType.bn, 10, declA)
    indexEvent(registry, EventType.created, ServiceType.bn, 10, declB)
    indexEvent(registry, EventType.active, ServiceType.bn, 20, declA)

    check getEventDeclarations(
      registry, EventType.created, ServiceType.bn, 10,
    ).len == 2
    check getEventDeclarations(
      registry, EventType.active, ServiceType.bn, 20,
    )[0] == declA
    check getEventDeclarations(
      registry, EventType.withdrawn, ServiceType.bn, 10,
    ).len == 0

{.pop.}
