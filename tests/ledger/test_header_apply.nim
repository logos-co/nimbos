# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  results,
  ../../logos_chain/ledger/ledger,
  ../core/mantle/test_helpers,
  ./sdp/test_helpers as sdp_test_helpers,
  ./test_helpers

from ../../logos_chain/core/types import ProofOfLeadership

func sentinelProof(): ProofOfLeadership =
  # All-default fields form the genesis sentinel, which bypasses Groth16
  # verification — lets these tests drive the epoch pipeline without a VK.
  ProofOfLeadership()

proc genesisLedgerState(): LedgerState =
  # One 1000-value note → total stake 1000; nonce fe(7). The epoch window
  # (base period 10, epoch length 100, snapshots 60/160) comes from
  # `testLedgerConfig`.
  LedgerState.fromUtxos(
    [mkUtxo(value = 1000)], fe(7), testSdpRegistry(), testLedgerConfig
  ).expect("genesis state")

suite "ledger/header apply (epoch pipeline)":
  test "applying a header advances the tracker":
    let
      genesis = genesisLedgerState()
      s = genesis.tryApplyHeader(5, sentinelProof(), testLedgerConfig).expect(
        "valid header")
    check:
      s.epochs.lastAppliedSlot == 5
      s.epochs.blockDensity.density == 1
      s.epochs.nonce != genesis.epochs.nonce # entropy rolled in
      s.epochs.activeEpoch.epoch == 0 # no rotation yet

  test "non-monotonic slot is rejected":
    let s = genesisLedgerState().tryApplyHeader(
      5, sentinelProof(), testLedgerConfig).expect("valid header")
    check:
      s.tryApplyHeader(5, sentinelProof(), testLedgerConfig).error == InvalidSlot
      s.tryApplyHeader(3, sentinelProof(), testLedgerConfig).error == InvalidSlot

  test "epoch rotation applies TSI to the observed density":
    # Three blocks inside the [0, 59] window; expected density is 6, so at
    # beta = 1 the estimate halves: 1000 → 500.
    var s = genesisLedgerState()
    for slot in [5'u64, 10, 20]:
      s = s.tryApplyHeader(slot, sentinelProof(), testLedgerConfig).expect("valid")
    check s.sdp.lastEpochStarted.isNone # no boundary crossed yet
    s = s.tryApplyHeader(100, sentinelProof(), testLedgerConfig).expect("rotation")
    check:
      s.epochs.activeEpoch.epoch == 1
      s.epochs.nextEpoch.epoch == 2
      s.epochs.activeEpoch.totalStake == 500
      s.epochs.blockDensity.periodStart == 100 # new window
      s.epochs.blockDensity.density == 1 # the rotating block itself
      # The rotating block also runs the SDP epoch boundary.
      s.sdp.lastEpochStarted == Opt.some(EpochNumber(1))

  test "nonce freezes at the snapshot slot, aged root at the epoch start":
    var s = genesisLedgerState()
    s = s.tryApplyHeader(50, sentinelProof(), testLedgerConfig).expect("valid")
    let nonceAfter50 = s.epochs.nonce
    # 65 ≥ 60 would freeze, but the chase runs with the PRE-block slot (50),
    # so the block at 65 still copies the running nonce...
    s = s.tryApplyHeader(65, sentinelProof(), testLedgerConfig).expect("valid")
    # ...and the block at 70 sees lastAppliedSlot = 65 ≥ 60: frozen.
    s = s.tryApplyHeader(70, sentinelProof(), testLedgerConfig).expect("valid")
    s = s.tryApplyHeader(100, sentinelProof(), testLedgerConfig).expect("rotation")
    check:
      s.epochs.activeEpoch.nonce == nonceAfter50 # η¹ = running nonce at last block < 60
      s.epochs.activeEpoch.agedUtxoRoot ==
        s.cryptarchiaLedger.latestUtxos.root # epoch 1 ages to the genesis root

  test "TSI chains across sequential epoch transitions":
    var s = genesisLedgerState()
    # Epoch 0: three blocks inside the [0, 59] window.
    for slot in [1'u64, 2, 3]:
      s = s.tryApplyHeader(slot, sentinelProof(), testLedgerConfig).expect("valid")
    check s.epochs.blockDensity.density == 3
    # A block outside the window is applied but not counted.
    s = s.tryApplyHeader(60, sentinelProof(), testLedgerConfig).expect("valid")
    check s.epochs.blockDensity.density == 3
    # Epoch 0 → 1: expected density 6, observed 3 → estimate halves at
    # beta = 1; the rotating block itself opens epoch 1's window.
    s = s.tryApplyHeader(100, sentinelProof(), testLedgerConfig).expect("rotation")
    check:
      s.epochs.activeEpoch.epoch == 1
      s.epochs.activeEpoch.totalStake == 500
      s.epochs.blockDensity.density == 1
    # Epoch 1: one more block inside [100, 159].
    s = s.tryApplyHeader(101, sentinelProof(), testLedgerConfig).expect("valid")
    check s.epochs.blockDensity.density == 2
    # Epoch 1 → 2: the estimate feeds forward from the inferred 500, not
    # from genesis: ⌊(500000 − ⌊500000·4000/6000⌋)/1000⌋ = 166.
    s = s.tryApplyHeader(200, sentinelProof(), testLedgerConfig).expect("rotation")
    check:
      s.epochs.activeEpoch.epoch == 2
      s.epochs.activeEpoch.totalStake == 166

  test "sibling branches rotate their epoch state independently":
    # The tracker is fork-local: children of the same parent state may land
    # in different epochs without affecting each other or the parent.
    let
      parent = genesisLedgerState().tryApplyHeader(
        5, sentinelProof(), testLedgerConfig).expect("valid")
      stay = parent.tryApplyHeader(
        50, sentinelProof(), testLedgerConfig).expect("valid")
      jump = parent.tryApplyHeader(
        250, sentinelProof(), testLedgerConfig).expect("rotation")
    check:
      stay.epochs.activeEpoch.epoch == 0
      stay.sdp.lastEpochStarted.isNone
      jump.epochs.activeEpoch.epoch == 2
      jump.sdp.lastEpochStarted == Opt.some(EpochNumber(2))
      parent.epochs.activeEpoch.epoch == 0
      parent.epochs.lastAppliedSlot == 5

  test "a note minted in epoch 0 enters the aged set only at epoch 2":
    # The stake distribution for epoch n freezes at the start of epoch n-1,
    # so a note minted mid-epoch-0 is absent from epoch 1's aged root and
    # present in epoch 2's.
    var s = genesisLedgerState()
    let genesisRoot = s.cryptarchiaLedger.latestUtxos.root
    s = s.tryApplyHeader(5, sentinelProof(), testLedgerConfig).expect("valid")
    s.cryptarchiaLedger = CryptarchiaState.init(
      [mkUtxo(value = 1000), mkUtxo(value = 50, pkSeed = 9)])
    let mintedRoot = s.cryptarchiaLedger.latestUtxos.root
    check mintedRoot != genesisRoot
    s = s.tryApplyHeader(100, sentinelProof(), testLedgerConfig).expect("rotation")
    check s.epochs.activeEpoch.agedUtxoRoot == genesisRoot
    s = s.tryApplyHeader(200, sentinelProof(), testLedgerConfig).expect("rotation")
    check s.epochs.activeEpoch.agedUtxoRoot == mintedRoot

  test "skipped epochs collapse the estimate with zero-density corrections":
    var s = genesisLedgerState()
    s = s.tryApplyHeader(5, sentinelProof(), testLedgerConfig).expect("valid")
    # Jump from epoch 0 straight to epoch 3 (slots 300–399): one inference
    # with the observed density, then two zero-density corrections. The
    # promoted state is seeded from the running nonce as of rotation time,
    # i.e. before the rotating block's own entropy is recorded.
    let nonceBeforeJump = s.epochs.nonce
    s = s.tryApplyHeader(350, sentinelProof(), testLedgerConfig).expect("rotation")
    check:
      s.epochs.activeEpoch.epoch == 3
      s.epochs.nextEpoch.epoch == 4
      s.epochs.activeEpoch.totalStake == 1 # beta = 1 zero-density floors D
      s.epochs.activeEpoch.nonce == nonceBeforeJump # nothing snapshotted: running values
      s.epochs.nonce != nonceBeforeJump # the rotating block still evolves the chain

  test "the blend target captures the outgoing epoch's chain values":
    # Two active blend providers at genesis, so the rotation freezes a
    # target. The target's quota-proof context must carry the epoch-0
    # values, not the state the rotation installs for epoch 1.
    var registry = testSdpRegistry()
    for seed in [byte 1, 2]:
      let
        declaration = DeclarationMessage(
          serviceType: ServiceType.bn,
          locators: @[mkLocator(30300 + int(seed))],
          providerId: mkProvider(seed),
          lockedNoteId: default(NoteId),
          zkId: fe(uint64(seed)))
        declId = installTestDeclaration(registry, declaration, 0)
      installTestActive(
        registry, ActiveMessage(declarationId: declId, nonce: 1), 0)
    registry = onEpochStarted(registry, 0)
    var s = LedgerState.fromUtxos(
      [mkUtxo(value = 1000)], fe(7), registry, testLedgerConfig
    ).expect("genesis state")
    # A block before the nonce snapshot makes epoch 1's nonce diverge from
    # epoch 0's, so the capture is observable.
    s = s.tryApplyHeader(5, sentinelProof(), testLedgerConfig).expect("valid")
    let outgoingNonce = s.epochs.activeEpoch.nonce
    s = s.tryApplyHeader(100, sentinelProof(), testLedgerConfig).expect(
      "rotation")
    check s.epochs.activeEpoch.nonce != outgoingNonce
    let target = s.sdp.blendRewards.target
    check target.isSome
    let public = target.get.state.poqPublic
    check:
      public.chain.polEpochNonce == outgoingNonce
      public.chain.polEpochNonce != s.epochs.activeEpoch.nonce
      public.coreRoot == coreZkIdRoot([fe(1), fe(2)]).get
      public.powQuota == 4

{.pop.}
