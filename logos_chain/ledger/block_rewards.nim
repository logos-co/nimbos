# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Per-block reward emission: the burned-fee look-back window and the
## leader/blend split of one block's emission.
## Spec: [Block Rewards](https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/block-rewards.md)

{.push raises: [], gcsafe.}

import
  stint,
  ../core/mantle/[gas, primitives]

const
  WINDOW_SIZE = 120 ## blocks of burned fees the emission formula looks back over
  # Names verbatim from the spec's integer formulation:
  # https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/block-rewards.md#float-precision-for-implementation
  A_SCALE = u128(120_000_000)
  FEE_AVG_NUMERATOR = u128(10_512)
  # Not one fraction: the numerator scales the inflation branch, the
  # denominator scales the fee-recycle branch.
  INFLATION_NUMERATOR = u128(62_500)
  INFLATION_DENOMINATOR = u128(657)
  STAKE_TARGET = u128(3_000_000_000)
  LEADER_SHARE_NUMERATOR = u128(4)
  BLEND_SHARE_NUMERATOR = u128(6)
  SHARE_DENOMINATOR = u128(10)

type FeeWindow* = object
  ## Burned fees of the last `WINDOW_SIZE` applied blocks, keyed
  ## `blockNumber mod WINDOW_SIZE`; zero-initialised at genesis.
  entries: array[WINDOW_SIZE, GasCost]

func update*(
    w: sink FeeWindow, blockNumber: uint64, burned: GasCost
): FeeWindow =
  ## Records `burned` in `blockNumber`'s slot, evicting the entry 120 blocks back.
  w.entries[blockNumber mod WINDOW_SIZE] = burned
  w

func summedFees*(w: FeeWindow): UInt128 =
  ## Burned fees summed over the whole window.
  # 120 * uint64.high needs 71 bits — the sum is only ever consumed in u128.
  for e in w.entries:
    result += u128(e)

func feeAt*(w: FeeWindow, blockNumber: uint64): GasCost =
  ## Burned fees recorded for `blockNumber`.
  w.entries[blockNumber mod WINDOW_SIZE]

func block_reward*(
    totalStake: uint64, sumFees: UInt128, lastBurnedFee: GasCost
): tuple[blend: Value, leader: Value] =
  ## Emission for one block, split 40/60; the caller adds tips to the leader share.
  let
    unclamped = STAKE_TARGET + FEE_AVG_NUMERATOR * sumFees
    stake = u128(totalStake)
    # min(max(target + fees - stake, 0), A_SCALE), compared before
    # subtracting: UInt128 has no negative range to clamp from.
    a =
      if stake >= unclamped:
        u128(0)
      else:
        min(unclamped - stake, A_SCALE)
    # Interpolates between pure inflation (a = A_SCALE) and pure fee
    # recycling (a = 0).
    rewardNumerator = INFLATION_NUMERATOR * a +
      INFLATION_DENOMINATOR * (A_SCALE - a) * u128(lastBurnedFee)
    shareDenominator = INFLATION_DENOMINATOR * A_SCALE * SHARE_DENOMINATOR
  # Each share truncates once, at the end; the 0-1 unit remainder is dropped.
  (blend: (rewardNumerator * BLEND_SHARE_NUMERATOR div shareDenominator)
     .truncate(uint64),
   leader: (rewardNumerator * LEADER_SHARE_NUMERATOR div shareDenominator)
     .truncate(uint64))

{.pop.}
