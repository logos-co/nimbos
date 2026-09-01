# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import results

from ../core/utils import NonNegativeRatio
from ../core/mantle/primitives import SlotNumber, EpochNumber

export results, NonNegativeRatio, SlotNumber, EpochNumber

type
  WallclockSeconds* = uint64

  EpochSchedule* = object
    ## Epoch-phase multipliers over the base period ⌊k/f⌋ (mainnet 3/3/4).
    basePeriodLength*: uint64 ## ⌊k/f⌋
    stakeDistributionStabilization*: uint64
    nonceBuffer*: uint64
    nonceStabilization*: uint64

  SlotConfig* = object
    ## Wallclock anchor for slot timing; `slotDurationSeconds` must be > 0.
    genesisTime*: WallclockSeconds ## start of the first epoch
    slotDurationSeconds*: uint64

func basePeriodLength*(securityParam: uint64, f: NonNegativeRatio): uint64 =
  ## ⌊k/f⌋ — expected slots to produce `k` blocks at slot-activation rate `f`.
  doAssert f.num > 0 and f.den > 0
  securityParam * f.den div f.num

func epochLength*(s: EpochSchedule): uint64 =
  (s.stakeDistributionStabilization + s.nonceBuffer + s.nonceStabilization) *
    s.basePeriodLength

func nonceContributionPeriod*(s: EpochSchedule): uint64 =
  ## Stake-distribution + buffer phases; also the TSI observation window.
  (s.stakeDistributionStabilization + s.nonceBuffer) * s.basePeriodLength

func slotToEpoch*(slot: SlotNumber, s: EpochSchedule): Opt[EpochNumber] =
  ## Epoch that contains `slot`. `none` past the epoch range.
  let epoch = slot div s.epochLength
  if epoch <= uint64(high(EpochNumber)):
    Opt.some(EpochNumber(epoch))
  else:
    Opt.none(EpochNumber)

func epochStartSlot*(epoch: EpochNumber, s: EpochSchedule): SlotNumber =
  uint64(epoch) * s.epochLength

func stakeDistributionSnapshot*(epoch: EpochNumber, s: EpochSchedule): SlotNumber =
  ## First slot of the previous epoch — where `epoch`'s eligible-note set
  ## freezes. Defined for `epoch >= 1`; epoch 0 is the hardcoded genesis state.
  doAssert epoch >= 1, "epoch-0 state is hardcoded at genesis"
  (uint64(epoch) - 1) * s.epochLength

func nonceSnapshot*(epoch: EpochNumber, s: EpochSchedule): SlotNumber =
  ## Slot where `epoch`'s nonce freezes — `6⌊k/f⌋` into the previous epoch.
  ## Defined for `epoch >= 1`; epoch 0 is the hardcoded genesis state.
  doAssert epoch >= 1, "epoch-0 state is hardcoded at genesis"
  (uint64(epoch) - 1) * s.epochLength + s.nonceContributionPeriod

func wallclockSlot*(
    now, genesis: WallclockSeconds, slotDuration: uint64): SlotNumber =
  ## Slot containing wallclock `now`; clamps to slot 0 before genesis.
  doAssert slotDuration > 0
  if now < genesis: 0'u64 else: (now - genesis) div slotDuration

func wallclockSlot*(now: WallclockSeconds, c: SlotConfig): SlotNumber =
  ## Slot for `now` under `c`.
  wallclockSlot(now, c.genesisTime, c.slotDurationSeconds)

{.pop.}
