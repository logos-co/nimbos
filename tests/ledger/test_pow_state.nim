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
  ../../logos_chain/ledger/pow_state,
  ./test_helpers

suite "ledger/pow_state":
  test "compute_new_reward_difficulty follows the spec formula":
    # T = 10, F = 9, P = 10: demand = 1 * claims + 9 * 10, and the new
    # target is 10 * current * 10 div demand.
    template cfg: untyped = testLedgerConfig.pow
    let cap = cfg.rewardTargetCap
    check:
      compute_new_reward_difficulty(10, 1_000.u256, cfg) == 1_000.u256 # 100_000 div 100
      compute_new_reward_difficulty(0, 1_000.u256, cfg) == 1_111.u256 # 100_000 div 90
      compute_new_reward_difficulty(200, 1_000.u256, cfg) == 344.u256 # 100_000 div 290
      # 900 div 290 = 3 is below the floor of 9.
      compute_new_reward_difficulty(200, 9.u256, cfg) == 9.u256
      # cap * 100 div 90 is above the cap.
      compute_new_reward_difficulty(0, cap, cfg) == cap
      # 900 div 90 = 10: the target at the floor rises again without claims.
      compute_new_reward_difficulty(0, 9.u256, cfg) == 10.u256
    # Without smoothing, an empty block gives a demand of 0. The formula
    # then uses 1, and the target is 10 * 1_000 * 10 div 1.
    var noSmoothing = testLedgerConfig.pow
    noSmoothing.emaSmoothingFactor = stuint(0, 512)
    check compute_new_reward_difficulty(
      0, 1_000.u256, noSmoothing) == 100_000.u256

  test "satisfies is true only for a ticket below the target":
    check:
      fe(4).satisfies(5.u256)
      not fe(5).satisfies(5.u256)
      not fe(6).satisfies(5.u256)

{.pop.}
