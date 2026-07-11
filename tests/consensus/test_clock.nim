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
  ../../logos_chain/time/clock,
  ./test_helpers

suite "time/clock":
  test "base period length is ⌊k/f⌋ for every deployment":
    check:
      basePeriodLength(5, NonNegativeRatio(num: 1, den: 2)) == 10
      basePeriodLength(2160, NonNegativeRatio(num: 1, den: 30)) == 64800 # mainnet
      basePeriodLength(30, NonNegativeRatio(num: 1, den: 20)) == 600 # devnet
      basePeriodLength(30, NonNegativeRatio(num: 1, den: 10)) == 300 # standalone

  test "epoch length is 10⌊k/f⌋":
    check testSchedule.epochLength == 100

  test "nonce contribution period is 6⌊k/f⌋":
    check testSchedule.nonceContributionPeriod == 60

  test "snapshot slots for epochs 1 and 2":
    check:
      stakeDistributionSnapshot(1, testSchedule) == 0
      stakeDistributionSnapshot(2, testSchedule) == 100
      nonceSnapshot(1, testSchedule) == 60
      nonceSnapshot(2, testSchedule) == 160

  test "slot to epoch round-trips across boundaries":
    check:
      slotToEpoch(0, testSchedule) == 0
      slotToEpoch(99, testSchedule) == 0
      slotToEpoch(100, testSchedule) == 1
      epochStartSlot(0, testSchedule) == 0
      epochStartSlot(1, testSchedule) == 100
      slotToEpoch(epochStartSlot(7, testSchedule), testSchedule) == 7
      slotToEpoch(epochStartSlot(7, testSchedule) - 1, testSchedule) == 6

  test "wallclock slot from genesis time":
    check:
      wallclockSlot(1000, 1000, 1) == 0
      wallclockSlot(1005, 1000, 1) == 5
      wallclockSlot(999, 1000, 1) == 0 # pre-genesis clamps to slot 0
      wallclockSlot(1011, 1000, 2) == 5

{.pop.}
