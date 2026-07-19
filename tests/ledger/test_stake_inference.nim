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
  ../../logos_chain/ledger/stake_inference

const
  # k = 10, f = 1/2 → base period 20, TSI window 6·20 = 120 slots,
  # expected density = 120 · 500 / 1000 = 60 blocks.
  testPeriod = 120'u64
  testBeta = fixedPoint(NonNegativeRatio(num: 1, den: 1))
  testF = fixedPoint(NonNegativeRatio(num: 1, den: 2))

suite "ledger/stake_inference":
  test "zero density collapses the estimate to the floor":
    check total_stake_inference(1000, 0, testPeriod, testBeta, testF) == 1

  test "high density raises the estimate":
    let estimate = total_stake_inference(1000, 120, testPeriod, testBeta, testF)
    check estimate > 1000
    check estimate == 2000 # measured = 2× expected doubles the estimate at beta = 1

  test "exact density keeps the estimate unchanged":
    check total_stake_inference(1000, 60, testPeriod, testBeta, testF) == 1000

  test "intermediate density lowers the estimate proportionally":
    check total_stake_inference(1000, 30, testPeriod, testBeta, testF) == 500

  test "smaller beta damps the correction":
    let halfBeta = fixedPoint(NonNegativeRatio(num: 1, den: 2))
    # measured = 2× expected: error is −tse, correction −tse/2 → 1.5× estimate.
    check total_stake_inference(1000, 120, testPeriod, halfBeta, testF) == 1500

  test "estimate at uint64.high stays in range":
    # Half the expected density halves the estimate at beta = 1; the
    # intermediate fixed-point products must not overflow at the maximum
    # representable stake.
    check total_stake_inference(uint64.high, 30, testPeriod, testBeta, testF) ==
      uint64.high div 2

  test "fixed-point parity per deployment":
    check:
      # beta_p: mainnet 1/1, devnet 1/2, standalone 1/10
      fixedPoint(NonNegativeRatio(num: 1, den: 1)) == 1000
      fixedPoint(NonNegativeRatio(num: 1, den: 2)) == 500
      fixedPoint(NonNegativeRatio(num: 1, den: 10)) == 100
      # f_p: mainnet 1/30, devnet 1/20, standalone 1/10
      fixedPoint(NonNegativeRatio(num: 1, den: 30)) == 33
      fixedPoint(NonNegativeRatio(num: 1, den: 20)) == 50
      fixedPoint(NonNegativeRatio(num: 1, den: 10)) == 100
      # 17 fractional digits: the ×Precision product exceeds uint64
      fixedPoint(NonNegativeRatio(
        num: 99999999999999999'u64, den: 100000000000000000'u64)) == 999

{.pop.}
