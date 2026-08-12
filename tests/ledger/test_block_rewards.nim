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
  stint,
  ../../logos_chain/core/mantle/[gas, primitives],
  ../../logos_chain/ledger/[balance, block_rewards, types]

template checkReward(
    totalStake: uint64,
    sumFees: UInt128,
    lastBurnedFee: GasCost,
    expectedLeader, expectedBlend: Value,
) =
  let r = block_reward(totalStake, sumFees, lastBurnedFee)
  check:
    r.leader == expectedLeader
    r.blend == expectedBlend

suite "block rewards: emission vectors":
  test "stake far below target pays pure inflation":
    checkReward(1_000'u64, u128(0), GasCost(0), 38'u64, 57'u64)

  test "the interpolation weight caps at A_SCALE":
    # target - stake = 120_000_000 exactly, so `a` sits on the clamp.
    checkReward(2_880_000_000'u64, u128(0), GasCost(0), 38'u64, 57'u64)

  test "stake above target pays pure fee recycling":
    checkReward(4_000_000_000'u64, u128(1_000), GasCost(1_000), 400'u64, 600'u64)

  test "half the interpolation weight halves the emission":
    checkReward(2_940_000_000'u64, u128(0), GasCost(0), 19'u64, 28'u64)

  test "fee recycling below one unit floors both shares to zero":
    checkReward(4_000_000_000'u64, u128(1), GasCost(1), 0'u64, 0'u64)

  test "the weight clamps to zero as soon as stake reaches target plus fees":
    # Compare-before-subtract boundary: at and past equality `a` is 0, so
    # only the fee-recycle branch pays.
    checkReward(3_000_000_000'u64, u128(0), GasCost(5), 2'u64, 3'u64)
    checkReward(3_000_000_001'u64, u128(0), GasCost(5), 2'u64, 3'u64)
    checkReward(uint64.high, u128(0), GasCost(5), 2'u64, 3'u64)

  test "a maximal burned fee stays inside the u128 numerator":
    # Widest reachable numerator: a = 0 and the whole u64 range burned.
    checkReward(
      uint64.high, u128(0), uint64.high,
      7_378_697_629_483_820_646'u64, 11_068_046_444_225_730_969'u64)

  test "an empty window with zero stake still emits":
    checkReward(0'u64, u128(0), GasCost(0), 38'u64, 57'u64)

suite "block rewards: fee window":
  test "an empty window sums to zero":
    check FeeWindow().summedFees == u128(0)

  test "summedFees includes the block just written":
    # The ledger writes before it reads, so the current block's burn is part
    # of the sum the emission formula sees.
    var w = FeeWindow()
    w.update(1, GasCost(700))
    w.update(2, GasCost(300))
    check w.summedFees == u128(1_000)

  test "block N + 120 evicts block N":
    var w = FeeWindow()
    w.update(5, GasCost(111))
    check w.summedFees == u128(111)
    w.update(125, GasCost(222)) # same ring slot
    check w.summedFees == u128(222)

  test "summedFees over a partial window sums only the written entries":
    var w = FeeWindow()
    for i in 1'u64 .. 4'u64:
      w.update(i, GasCost(i * 10))
    check w.summedFees == u128(100)

  test "a full window of maximal entries stays inside u128":
    var w = FeeWindow()
    for i in 1'u64 .. 120'u64:
      w.update(i, uint64.high)
    check w.summedFees == u128(120) * u128(uint64.high)
    # 10_512 * that sum dwarfs STAKE_TARGET, so the weight pins at A_SCALE.
    checkReward(0'u64, w.summedFees, uint64.high, 38'u64, 57'u64)

suite "block rewards: balance narrowing":
  test "values up to uint64.high narrow unchanged":
    check:
      checked_uint64(Balance.zero).get == 0'u64
      checked_uint64(1'u64.to(Balance)).get == 1'u64
      checked_uint64(uint64.high.to(Balance)).get == uint64.high

  test "values outside the Value range are rejected, never wrapped":
    let beyond = uint64.high.to(Balance) + 1'u64.to(Balance) # 2^64
    check:
      checked_uint64(beyond).error == BalanceOutOfRange
      checked_uint64(beyond + 5'u64.to(Balance)).error == BalanceOutOfRange
      checked_uint64(Balance.zero - 1'u64.to(Balance)).error == BalanceOutOfRange

{.pop.}
