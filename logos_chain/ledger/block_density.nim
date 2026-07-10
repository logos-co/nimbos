# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import ../time/clock

export clock

type BlockDensity* = object
  ## Block counter over the total-stake-inference observation window.
  periodStart*: SlotNumber ## inclusive
  periodEnd*: SlotNumber ## inclusive
  density*: uint64

func init*(T: type BlockDensity, epoch: EpochNumber, s: EpochSchedule): T =
  ## Measurement window for `epoch`: the `6⌊k/f⌋` slots ending just before
  ## `nonceSnapshot(epoch + 1)`, i.e. the epoch's first two phases.
  T(periodStart: epochStartSlot(epoch, s),
    periodEnd: nonceSnapshot(epoch + 1, s) - 1,
    density: 0)

func increment*(bd: BlockDensity, slot: SlotNumber): BlockDensity =
  ## Counts `slot` only if it falls inside the measurement window.
  var next = bd
  if slot >= bd.periodStart and slot <= bd.periodEnd:
    inc next.density
  next

{.pop.}
