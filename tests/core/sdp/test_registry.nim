# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/tables,
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

suite "core/sdp/registry — session snapshots":
  const SessionLen = 10'u64

  proc withShortSessions(registry: var SdpRegistry) =
    appendParameters(registry, ServiceType.bn, ServiceParameters(
      sessionLength: SessionLen, lockPeriod: 1, timestamp: 0,
    ), TestSecurityParam)

  test "sessions 0 and 1 use genesis snapshot at block 0":
    var registry = testSdpRegistry()
    withShortSessions(registry)
    onBlockApplied(registry, previousBlockNumber = 0, blockNumber = 0)
    check getSessionSnapshot(registry.index.sessions, ServiceType.bn, 0).isSome
    check getSessionSnapshot(registry.index.sessions, ServiceType.bn, 1).isSome
    check getSessionSnapshot(registry.index.sessions, ServiceType.bn, 0).get() ==
      getSessionSnapshot(registry.index.sessions, ServiceType.bn, 1).get()

    var declId: DeclarationId
    declId[0] = 1
    registry.state = insertDeclaration(
      registry.state, declId,
      DeclarationInfo(
        service: ServiceType.bn,
        providerId: mkProvider(1),
        lockedNoteId: default(NoteId),
        zkId: default(ZkPublicKey),
        locators: @[],
        created: 1,
        active: 1,
        withdrawn: 0,
        nonce: 0,
      ),
    )
    check getSessionSnapshot(registry.index.sessions, ServiceType.bn, 0).get()
      .declarations.len == 0

  test "takes S_n when session n-1 starts":
    var registry = testSdpRegistry()
    withShortSessions(registry)
    onBlockApplied(registry, previousBlockNumber = 9, blockNumber = 10)
    check getSessionSnapshot(registry.index.sessions, ServiceType.bn, 2).isSome

  test "takes next snapshot and prunes ended session on boundary":
    var registry = testSdpRegistry()
    withShortSessions(registry)
    onBlockApplied(registry, previousBlockNumber = 9, blockNumber = 10)
    check getSessionSnapshot(registry.index.sessions, ServiceType.bn, 2).isSome

    onBlockApplied(registry, previousBlockNumber = 19, blockNumber = 20)
    check getSessionSnapshot(registry.index.sessions, ServiceType.bn, 2).isSome
    check getSessionSnapshot(registry.index.sessions, ServiceType.bn, 3).isSome

    onBlockApplied(registry, previousBlockNumber = 29, blockNumber = 30)
    check getSessionSnapshot(registry.index.sessions, ServiceType.bn, 2).isNone
    check getSessionSnapshot(registry.index.sessions, ServiceType.bn, 3).isSome
    check getSessionSnapshot(registry.index.sessions, ServiceType.bn, 4).isSome

  test "snapshots are isolated from later live state":
    var registry = testSdpRegistry()
    withShortSessions(registry)
    onBlockApplied(registry, previousBlockNumber = 9, blockNumber = 10)
    let snap2 = getSessionSnapshot(registry.index.sessions, ServiceType.bn, 2).get()
    check snap2.declarations.len == 0

    var declId: DeclarationId
    declId[0] = 1
    registry.state = insertDeclaration(
      registry.state, declId,
      DeclarationInfo(
        service: ServiceType.bn,
        providerId: mkProvider(1),
        lockedNoteId: default(NoteId),
        zkId: default(ZkPublicKey),
        locators: @[],
        created: 15,
        active: 15,
        withdrawn: 0,
        nonce: 0,
      ),
    )
    check registry.state.declarations.len == 1
    check getSessionSnapshot(registry.index.sessions, ServiceType.bn, 2).get()
      .declarations.len == 0

  test "retains at most two session snapshots in steady state":
    var registry = testSdpRegistry()
    withShortSessions(registry)
    for i in 1 .. 6:
      let boundary = uint64(i) * SessionLen
      onBlockApplied(
        registry,
        previousBlockNumber = boundary - 1,
        blockNumber = boundary,
      )
      check registry.index.sessions.getOrDefault(ServiceType.bn).len <= 2

{.pop.}
