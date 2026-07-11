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
  ../../logos_chain/ledger/ledger,
  ./test_helpers

# k = 1, f = 1/10 → base period 10, epoch length 100, nonce snapshots at
# 60/160, TSI window [0, 59] for epoch 0 with expected density 6.
# f = 1/10 keeps the lottery-constants lookup satisfied (standalone entry).
const testConfig = LedgerConfig(
  epochSchedule: testSchedule,
  slotActivationCoeff: NonNegativeRatio(num: 1, den: 10),
  stakeInferenceLearningRate: NonNegativeRatio(num: 1, den: 1))

func sentinelProof(): ProofOfLeadership =
  # All-default fields form the genesis sentinel, which bypasses Groth16
  # verification — lets these tests drive the epoch pipeline without a VK.
  ProofOfLeadership()

proc genesisLedgerState(): LedgerState =
  LedgerState.fromGenesis([], fe(7), 1000, testConfig).expect("genesis epochs")

suite "ledger/header apply (epoch pipeline)":
  test "applying a header advances the tracker":
    let
      genesis = genesisLedgerState()
      s = genesis.tryApplyHeader(5, sentinelProof(), testConfig).expect(
        "valid header")
    check:
      s.epochs.lastAppliedSlot == 5
      s.epochs.blockDensity.density == 1
      s.epochs.nonce != genesis.epochs.nonce # entropy rolled in
      s.epochs.activeEpoch.epoch == 0 # no rotation yet

  test "non-monotonic slot is rejected":
    let s = genesisLedgerState().tryApplyHeader(
      5, sentinelProof(), testConfig).expect("valid header")
    check:
      s.tryApplyHeader(5, sentinelProof(), testConfig).error == InvalidSlot
      s.tryApplyHeader(3, sentinelProof(), testConfig).error == InvalidSlot

  test "epoch rotation applies TSI to the observed density":
    # Three blocks inside the [0, 59] window; expected density is 6, so at
    # beta = 1 the estimate halves: 1000 → 500.
    var s = genesisLedgerState()
    for slot in [5'u64, 10, 20]:
      s = s.tryApplyHeader(slot, sentinelProof(), testConfig).expect("valid")
    s = s.tryApplyHeader(100, sentinelProof(), testConfig).expect("rotation")
    check:
      s.epochs.activeEpoch.epoch == 1
      s.epochs.nextEpoch.epoch == 2
      s.epochs.activeEpoch.totalStake == 500
      s.epochs.blockDensity.periodStart == 100 # new window
      s.epochs.blockDensity.density == 1 # the rotating block itself

  test "nonce freezes at the snapshot slot, aged root at the epoch start":
    var s = genesisLedgerState()
    s = s.tryApplyHeader(50, sentinelProof(), testConfig).expect("valid")
    let nonceAfter50 = s.epochs.nonce
    # 65 ≥ 60 would freeze, but the chase runs with the PRE-block slot (50),
    # so the block at 65 still copies the running nonce...
    s = s.tryApplyHeader(65, sentinelProof(), testConfig).expect("valid")
    # ...and the block at 70 sees lastAppliedSlot = 65 ≥ 60: frozen.
    s = s.tryApplyHeader(70, sentinelProof(), testConfig).expect("valid")
    s = s.tryApplyHeader(100, sentinelProof(), testConfig).expect("rotation")
    check:
      s.epochs.activeEpoch.nonce == nonceAfter50 # η¹ = running nonce at last block < 60
      s.epochs.activeEpoch.agedUtxoRoot ==
        s.cryptarchiaLedger.latestUtxos.root # epoch 1 ages to the genesis root

  test "skipped epochs collapse the estimate with zero-density corrections":
    var s = genesisLedgerState()
    s = s.tryApplyHeader(5, sentinelProof(), testConfig).expect("valid")
    # Jump from epoch 0 straight to epoch 3 (slots 300–399): one inference
    # with the observed density, then two zero-density corrections. The
    # promoted state is seeded from the running nonce as of rotation time,
    # i.e. before the rotating block's own entropy is recorded.
    let nonceBeforeJump = s.epochs.nonce
    s = s.tryApplyHeader(350, sentinelProof(), testConfig).expect("rotation")
    check:
      s.epochs.activeEpoch.epoch == 3
      s.epochs.nextEpoch.epoch == 4
      s.epochs.activeEpoch.totalStake == 1 # beta = 1 zero-density floors D
      s.epochs.activeEpoch.nonce == nonceBeforeJump # nothing snapshotted: running values
      s.epochs.nonce != nonceBeforeJump # the rotating block still evolves the chain

  test "zero schedule keeps the legacy scaffold path":
    let s = LedgerState.fromUtxos([]).tryApplyHeader(
      5, sentinelProof(), LedgerConfig()).expect("scaffold mode")
    check s.epochs.lastAppliedSlot == 0 # pipeline skipped

{.pop.}
