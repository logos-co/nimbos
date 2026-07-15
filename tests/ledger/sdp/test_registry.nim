# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  results,
  std/tables,
  unittest2,
  ../../../logos_chain/ledger/sdp/registry,
  ./test_helpers

suite "ledger/sdp/registry":
  test "stores service parameters per service":
    var registry = testSdpRegistry()
    check registry.params.parameters.len == 1
    check getParametersAt(registry, ServiceType.bn, 100).isSome

    appendParameters(registry, ServiceType.bn, ServiceParameters(
      inactivityPeriod: 2, epoch: 0,
    ))
    check registry.params.parameters.len == 1
    check getParametersAt(registry, ServiceType.bn, 100).get().inactivityPeriod == 2'u64

    appendParameters(registry, ServiceType.bn, ServiceParameters(
      inactivityPeriod: 3, epoch: 50,
    ))
    check registry.params.parameters.len == 1
    check getParametersAt(registry, ServiceType.bn, 25).isNone
    check getParametersAt(registry, ServiceType.bn, 50).get().inactivityPeriod == 3'u64

  test "stores versioned minimum stake entries":
    var registry = testSdpRegistry()
    check registry.params.stakeThresholds.len == 1
    check getMinStakeAt(registry, 100).isSome

    appendMinStake(registry, MinStake(stakeThreshold: 1000, epoch: 0))
    appendMinStake(registry, MinStake(stakeThreshold: 2000, epoch: 50))
    check registry.params.stakeThresholds.len == 3
    check getMinStakeAt(registry, 25).get().stakeThreshold == 1000'u64
    check getMinStakeAt(registry, 50).get().stakeThreshold == 2000'u64
    check getMinStakeAt(registry, 100).get().stakeThreshold == 2000'u64

  test "bundles state, snapshots, and params":
    var registry = testSdpRegistry()
    check registry.state.declarations.len == 0
    check registry.snapshots.len == 0
    check registry.params.parameters.len == 1
    check registry.params.stakeThresholds.len == 1

  test "onEpochStarted finalizes pending withdrawals":
    var seeded = seedDeclaration(pkSeed = 30, declareEpoch = 1)
    let withdraw = WithdrawMessage(
      declarationId: seeded.declId,
      lockedNoteId: seeded.declaration.lockedNoteId,
      nonce: 1,
    )
    installTestWithdraw(seeded.registry, withdraw, 5)
    check getDeclaration(seeded.registry.state, seeded.declId).isSome
    onEpochStarted(seeded.registry, 7)
    check getDeclaration(seeded.registry.state, seeded.declId).isNone

  test "onEpochStarted skips finalization when epoch unchanged":
    var seeded = seedDeclaration(pkSeed = 31, declareEpoch = 1)
    let withdraw = WithdrawMessage(
      declarationId: seeded.declId,
      lockedNoteId: seeded.declaration.lockedNoteId,
      nonce: 1,
    )
    installTestWithdraw(seeded.registry, withdraw, 5)
    for epoch in 1'u64 .. 6'u64:
      onEpochStarted(seeded.registry, epoch)
    check getDeclaration(seeded.registry.state, seeded.declId).isSome
    onEpochStarted(seeded.registry, 7)
    check getDeclaration(seeded.registry.state, seeded.declId).isNone
    onEpochStarted(seeded.registry, 7)
    check getDeclaration(seeded.registry.state, seeded.declId).isNone

suite "ledger/sdp/registry — epoch snapshots":
  test "epochs 0 and 1 use genesis snapshot":
    var registry = testSdpRegistry()
    onEpochStarted(registry, 0)
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 0).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 1).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 0).get() ==
      getEpochSnapshot(registry.snapshots, ServiceType.bn, 1).get()

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
        active: Opt.none(EpochNumber),
        withdrawAt: Opt.none(EpochNumber),
        nonce: 0,
      ),
    )
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 0).get()
      .declarations.len == 0

  test "takes S_n when epoch n-2 starts":
    var registry = testSdpRegistry()
    onEpochStarted(registry, 1)
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).isSome

  test "takes next snapshot and prunes ended epoch on boundary":
    var registry = testSdpRegistry()
    onEpochStarted(registry, 1)
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).isSome

    onEpochStarted(registry, 2)
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 4).isSome

    onEpochStarted(registry, 3)
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 4).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 5).isSome

    onEpochStarted(registry, 4)
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).isNone
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 4).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 5).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 6).isSome

  test "snapshots are isolated from later live state":
    var registry = testSdpRegistry()
    onEpochStarted(registry, 1)
    let snap3 = getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).get()
    check snap3.declarations.len == 0

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
        created: 2,
        active: Opt.none(EpochNumber),
        withdrawAt: Opt.none(EpochNumber),
        nonce: 0,
      ),
    )
    check registry.state.declarations.len == 1
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).get()
      .declarations.len == 0

  test "retains at most three epoch snapshots in steady state":
    var registry = testSdpRegistry()
    for epoch in 1'u64 .. 6'u64:
      onEpochStarted(registry, epoch)
      check registry.snapshots.getOrDefault(ServiceType.bn).len <= 3

  test "prunes all ended snapshots when epochs are skipped":
    var registry = testSdpRegistry()
    onEpochStarted(registry, 1)
    onEpochStarted(registry, 2)
    onEpochStarted(registry, 3)
    check registry.snapshots.getOrDefault(ServiceType.bn).len == 3
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 4).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 5).isSome

    onEpochStarted(registry, 7)
    let byEpoch = registry.snapshots.getOrDefault(ServiceType.bn)
    check byEpoch.len == 1
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).isNone
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 4).isNone
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 5).isNone
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 9).isSome

{.pop.}
