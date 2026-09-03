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
  stint,
  ../../logos_chain/ledger/epoch_state,
  ../../logos_chain/zk/groth16/utils,
  ./test_helpers

const FieldModulusMinusOne =
  "21888242871839275222246405745257275088548364400416034343698204186575808495616"

suite "ledger/blend_difficulty — integer_nth_root":
  test "exact floor around a perfect square":
    let k = stuint(123_456_789'u64, 512)
    check:
      integer_nth_root(k * k, 2) == k
      integer_nth_root(k * k - 1, 2) == k - 1
      integer_nth_root(k * k + 1, 2) == k

  test "degenerate inputs":
    check:
      integer_nth_root(stuint(0, 512), 2) == stuint(0, 512)
      integer_nth_root(stuint(1, 512), 2) == stuint(1, 512)
      integer_nth_root(stuint(8, 512), 1) == stuint(8, 512)

  test "values near the 512-bit bound keep the exact floor":
    # The largest base whose square still fits 512 bits. A naive
    # bit-length seed would overflow the first midpoint square here.
    let k = (stuint(1, 512) shl 256) - 1
    check:
      integer_nth_root(k * k, 2) == k
      integer_nth_root(k * k - 1, 2) == k - 1

  test "a power-of-two radicand":
    let k = stuint(1, 512) shl 255
    check integer_nth_root(k * k, 2) == k

suite "ledger/blend_difficulty — retarget controller":
  # A load is the pair of blocks and txs. The reference ratio is
  # txs == TARGET_TXS_PER_BLOCK * blocks.
  let base = BlendDifficultyBaseFr

  test "the reference load sits at the baseline":
    check compute_epoch_blend_difficulty(
      EpochLoad(blocks: 7, txs: 7 * TARGET_TXS_PER_BLOCK), base) == base

  test "no load eases as far as the clamp allows":
    # 2 * base stays below the modulus, so the field addition below is
    # the integer doubling.
    check compute_epoch_blend_difficulty(EpochLoad(txs: 0), base) ==
      base + base

  test "a quarter of the reference load hits the upward clamp":
    # target = base * 2 exactly, which is the clamp ceiling.
    check compute_epoch_blend_difficulty(
      EpochLoad(blocks: 4, txs: TARGET_TXS_PER_BLOCK), base) == base + base

  test "heavy load hits the downward clamp":
    # Load ratio 4 gives target = base div 2 = the clamp floor exactly;
    # ratio 16 gives base div 4, clamped up to the same floor.
    let
      atFloor = compute_epoch_blend_difficulty(
        EpochLoad(blocks: 1, txs: 4 * TARGET_TXS_PER_BLOCK), base)
      clamped = compute_epoch_blend_difficulty(
        EpochLoad(blocks: 1, txs: 16 * TARGET_TXS_PER_BLOCK), base)
    check:
      atFloor == clamped
      atFloor != base

  test "the result is capped below the field modulus":
    let previous = frFromDecimal(FieldModulusMinusOne).expect("p - 1 parses")
    check compute_epoch_blend_difficulty(EpochLoad(txs: 0), previous) ==
      previous

suite "ledger/blend_difficulty — load tracking":
  test "blocks and transactions accumulate":
    var d = TxDensity()
    d = d.recordBlock(3)
    d = d.recordBlock(0)
    d = d.recordBlock(7)
    check:
      d.currentEpoch == EpochLoad(blocks: 3, txs: 10)
      d.lastClosedEpoch.isNone
      d.lastClosedOrEmpty() == EpochLoad()

  test "closing moves the totals and resets the open epoch":
    var d = TxDensity()
    d = d.recordBlock(5)
    d = d.closeEpoch()
    check:
      d.lastClosedOrEmpty() == EpochLoad(blocks: 1, txs: 5)
      d.currentEpoch == EpochLoad()
    # A second close with no blocks reads as a skipped epoch.
    d = d.closeEpoch()
    check d.lastClosedOrEmpty() == EpochLoad()

  test "transaction totals accept the full uint64 range":
    # Overflow past the range is a checked invariant, not a saturation.
    # The boundary itself is representable and must count normally.
    var d = TxDensity()
    d = d.recordBlock(high(uint64))
    d = d.recordBlock(0)
    check d.currentEpoch == EpochLoad(blocks: 2, txs: high(uint64))

suite "ledger/blend_difficulty — epoch timing":
  # testSchedule: 100-slot epochs.
  let base = BlendDifficultyBaseFr

  proc genesisTracker(): EpochTracker =
    genesisEpochTracker(fe(7), fe(9), 1000, testLedgerConfig).expect(
      "supported f")

  test "genesis seeds both epochs with the base value":
    let t = genesisTracker()
    check:
      t.activeEpoch.powBlendDifficulty == base
      t.nextEpoch.powBlendDifficulty == base

  test "epoch 2's value derives from epoch 0's load":
    var t = genesisTracker()
    t = t.recordBlockTxs(700)
    t = t.recordBlockTxs(700)
    # Cross into epoch 1: epoch 1 keeps the base, epoch 2 is seeded from
    # epoch 0's closed load and epoch 1's value.
    let advanced = t.advanceEpochs(105, fe(9), testLedgerConfig).expect(
      "advance to epoch 1")
    check:
      advanced.activeEpoch.epoch == 1
      advanced.activeEpoch.powBlendDifficulty == base
      advanced.nextEpoch.powBlendDifficulty ==
        compute_epoch_blend_difficulty(
          EpochLoad(blocks: 2, txs: 1400), base)
      advanced.txDensity.lastClosedOrEmpty() ==
        EpochLoad(blocks: 2, txs: 1400)
      advanced.txDensity.currentEpoch == EpochLoad()

  test "skipped epochs compound one clamp step per epoch":
    var t = genesisTracker()
    t = t.recordBlockTxs(50)
    # Jump from epoch 0 straight into epoch 3: epochs 1 and 2 close empty.
    let advanced = t.advanceEpochs(305, fe(9), testLedgerConfig).expect(
      "advance to epoch 3")
    let
      d2 = compute_epoch_blend_difficulty(EpochLoad(blocks: 1, txs: 50), base)
      d3 = compute_epoch_blend_difficulty(EpochLoad(), d2)
    check:
      advanced.activeEpoch.epoch == 3
      advanced.activeEpoch.powBlendDifficulty == d3
      advanced.nextEpoch.powBlendDifficulty ==
        compute_epoch_blend_difficulty(EpochLoad(), d3)
      advanced.txDensity.lastClosedOrEmpty() == EpochLoad()

  test "trackers fork by value — counting in one leaves the other alone":
    let t = genesisTracker()
    let branch = t.recordBlockTxs(9)
    check:
      t.txDensity.currentEpoch == EpochLoad()
      branch.txDensity.currentEpoch == EpochLoad(blocks: 1, txs: 9)

{.pop.}
