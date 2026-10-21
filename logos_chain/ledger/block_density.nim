# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  ../consensus/clock,
  ../utils/hash_trie_map

export clock

type BlockDensity* = object
  ## Occupied-slot set over the total-stake-inference observation window.
  periodStart*: SlotNumber ## inclusive
  periodEnd*: SlotNumber ## inclusive
  occupied: HashTrieMap[SlotNumber, tuple[]] ## distinct slots counted so far

func init*(T: type BlockDensity, epoch: EpochNumber, s: EpochSchedule): T =
  ## Measurement window for `epoch`: the `6⌊k/f⌋` slots ending just before
  ## `nonceSnapshot(epoch + 1)`, i.e. the epoch's first two phases.
  T(periodStart: epochStartSlot(epoch, s),
    periodEnd: nonceSnapshot(epoch + 1, s) - 1)

func inWindow(bd: BlockDensity, slot: SlotNumber): bool =
  slot >= bd.periodStart and slot <= bd.periodEnd

func markOccupied*(
    bd: BlockDensity, blockSlot: SlotNumber, uncleSlots: openArray[SlotNumber],
): BlockDensity =
  ## Counts `blockSlot` and each in-window uncle slot. A slot counts once.
  # A block outside the window adds nothing, not even its in-window uncles.
  if not bd.inWindow(blockSlot):
    return bd
  var next = bd
  next.occupied = next.occupied.insert(blockSlot, ())
  for slot in uncleSlots:
    if bd.inWindow(slot):
      next.occupied = next.occupied.insert(slot, ())
  next

func density*(bd: BlockDensity): uint64 =
  ## Number of distinct occupied slots counted so far.
  uint64(bd.occupied.len)

{.pop.}
