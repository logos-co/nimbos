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
    seeded.registry = onEpochStarted(seeded.registry, 7)
    check getDeclaration(seeded.registry.state, seeded.declId).isNone

  test "onEpochStarted asserts when the epoch does not advance":
    var seeded = seedDeclaration(pkSeed = 31, declareEpoch = 1)
    let withdraw = WithdrawMessage(
      declarationId: seeded.declId,
      lockedNoteId: seeded.declaration.lockedNoteId,
      nonce: 1,
    )
    installTestWithdraw(seeded.registry, withdraw, 5)
    for epoch in 1'u64 .. 6'u64:
      seeded.registry = onEpochStarted(seeded.registry, epoch)
    check getDeclaration(seeded.registry.state, seeded.declId).isSome
    seeded.registry = onEpochStarted(seeded.registry, 7)
    check getDeclaration(seeded.registry.state, seeded.declId).isNone
    expect AssertionDefect:
      discard onEpochStarted(seeded.registry, 7)

suite "ledger/sdp/registry — epoch snapshots":
  test "epochs 0 and 1 use genesis snapshot":
    var registry = testSdpRegistry()
    registry = onEpochStarted(registry, 0)
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
    registry = onEpochStarted(registry, 1)
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 2).isSome

  test "takes next snapshot and prunes ended epoch on boundary":
    var registry = testSdpRegistry()
    registry = onEpochStarted(registry, 1)
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 2).isSome

    registry = onEpochStarted(registry, 2)
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 2).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).isSome

    registry = onEpochStarted(registry, 3)
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 2).isNone
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 4).isSome

    registry = onEpochStarted(registry, 4)
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).isNone
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 4).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 5).isSome

  test "snapshots are isolated from later live state":
    var registry = testSdpRegistry()
    registry = onEpochStarted(registry, 1)
    let snap2 = getEpochSnapshot(registry.snapshots, ServiceType.bn, 2).get()
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
        created: 2,
        active: Opt.none(EpochNumber),
        withdrawAt: Opt.none(EpochNumber),
        nonce: 0,
      ),
    )
    check registry.state.declarations.len == 1
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 2).get()
      .declarations.len == 0

  test "retains at most three epoch snapshots in steady state":
    var registry = testSdpRegistry()
    for epoch in 1'u64 .. 6'u64:
      registry = onEpochStarted(registry, epoch)
      check registry.snapshots.getOrDefault(ServiceType.bn).len <= 3

  test "prunes all ended snapshots when epochs are skipped":
    var registry = testSdpRegistry()
    registry = onEpochStarted(registry, 1)
    registry = onEpochStarted(registry, 2)
    registry = onEpochStarted(registry, 3)
    check registry.snapshots.getOrDefault(ServiceType.bn).len == 2
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 4).isSome

    registry = onEpochStarted(registry, 7)
    # The skipped boundaries backfill their snapshot keys, so the live
    # targets 7 and 8 both exist and only the ended ones are pruned.
    let byEpoch = registry.snapshots.getOrDefault(ServiceType.bn)
    check byEpoch.len == 2
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 3).isNone
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 4).isNone
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 7).isSome
    check getEpochSnapshot(registry.snapshots, ServiceType.bn, 8).isSome

suite "ledger/sdp/registry — active blend providers":
  test "a fresh declaration is active from its first snapshot":
    var seeded = seedDeclaration(pkSeed = 40, declareEpoch = 1)
    seeded.registry = onEpochStarted(seeded.registry, 1)
    let providers = activeBlendProviders(seeded.registry, 2)
    check providers.len == 1
    check providers[0].providerId == seeded.declaration.providerId
    check providers[0].zkId == seeded.declaration.zkId

  test "a provider drops out once the inactivity period lapses":
    var seeded = seedDeclaration(pkSeed = 41, declareEpoch = 1)
    installTestActive(seeded.registry, ActiveMessage(
      declarationId: seeded.declId, nonce: 1, metadata: @[]), 1)
    seeded.registry = onEpochStarted(seeded.registry, 2)
    seeded.registry = onEpochStarted(seeded.registry, 3)
    # Last activity in epoch 1 plus an inactivity period of 2 reaches epoch 3.
    check activeBlendProviders(seeded.registry, 3).len == 1
    check activeBlendProviders(seeded.registry, 4).len == 0

  test "a pending withdrawal excludes the provider once it takes effect":
    var seeded = seedDeclaration(pkSeed = 42, declareEpoch = 1)
    installTestWithdraw(seeded.registry, WithdrawMessage(
      declarationId: seeded.declId,
      lockedNoteId: seeded.declaration.lockedNoteId,
      nonce: 1), 3)
    seeded.registry = onEpochStarted(seeded.registry, 1)
    seeded.registry = onEpochStarted(seeded.registry, 2)
    check activeBlendProviders(seeded.registry, 2).len == 1
    check activeBlendProviders(seeded.registry, 3).len == 0

  test "a missing epoch snapshot yields no providers":
    check activeBlendProviders(testSdpRegistry(), 5).len == 0

  test "service parameters not yet in force yield no providers":
    var seeded = seedDeclaration(pkSeed = 43, declareEpoch = 1)
    appendParameters(seeded.registry, ServiceType.bn, ServiceParameters(
      inactivityPeriod: 2, epoch: 10,
    ))
    seeded.registry = onEpochStarted(seeded.registry, 1)
    # Epoch boundaries skip a service whose parameters are not yet in
    # force, so no snapshot exists and the provider set is empty.
    check getEpochSnapshot(seeded.registry.snapshots, ServiceType.bn, 2).isNone
    check activeBlendProviders(seeded.registry, 2).len == 0

  test "an empty epoch leaves no snapshot hole":
    var seeded = seedDeclaration(pkSeed = 44, declareEpoch = 1)
    seeded.registry = onEpochStarted(seeded.registry, 1)
    # Epoch 2 produced no blocks, so its boundary never ran; the next
    # boundary at epoch 3 must backfill the skipped snapshot key.
    seeded.registry = onEpochStarted(seeded.registry, 3)
    check getEpochSnapshot(seeded.registry.snapshots, ServiceType.bn, 3).isSome
    check activeBlendProviders(seeded.registry, 3).len == 1

{.pop.}
