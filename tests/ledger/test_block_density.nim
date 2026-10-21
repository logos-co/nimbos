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
  ../../logos_chain/ledger/block_density,
  ./test_helpers

suite "ledger/block_density":
  test "initial density is zero and epoch-0 window starts at slot 0":
    let bd = BlockDensity.init(0, testSchedule)
    check:
      bd.periodStart == 0
      bd.periodEnd == 59
      bd.density == 0

  test "markOccupied counts only slots inside the window":
    var bd = BlockDensity.init(1, testSchedule)
    check:
      bd.periodStart == 100
      bd.periodEnd == 159
    bd = bd.markOccupied(100, [])
    check bd.density == 1
    bd = bd.markOccupied(159, [])
    check bd.density == 2
    bd = bd.markOccupied(140, []) # slot order does not matter
    check bd.density == 3
    bd = bd.markOccupied(95, []) # before the window: ignored
    check bd.density == 3
    bd = bd.markOccupied(160, []) # after the window: ignored
    check bd.density == 3

  test "each distinct uncle slot in a block counts once":
    let bd = BlockDensity.init(1, testSchedule).markOccupied(110, [105'u64, 106, 105])
    check bd.density == 3

  test "an uncle slot outside the window is ignored":
    let bd = BlockDensity.init(1, testSchedule).markOccupied(110, [99'u64, 160])
    check bd.density == 1

  test "a block outside the window adds nothing, even with in-window uncles":
    let bd = BlockDensity.init(1, testSchedule).markOccupied(160, [150'u64])
    check bd.density == 0

  test "an uncle at the slot of an earlier chain block adds nothing":
    let bd = BlockDensity.init(1, testSchedule)
      .markOccupied(110, [])
      .markOccupied(120, [110'u64])
    check bd.density == 2

{.pop.}
