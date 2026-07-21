# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import stint

from ../core/utils import NonNegativeRatio

export NonNegativeRatio

const
  Precision = 1000'u64 ## fixed-point scale — spec-pinned
  One128 = 1'u64.i128
  MaxUint64128 = uint64.high.i128

func fixedPoint*(r: NonNegativeRatio): uint64 =
  ## `truncate(r × Precision)` computed exactly in integers.
  doAssert r.den > 0
  let scaled = r.num.u128 * Precision.u128 div r.den.u128
  doAssert scaled <= uint64.high.u128, "fixed-point value exceeds uint64"
  scaled.truncate(uint64)

# https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/cryptarchia-total-stake-inference.md#algorithm
func total_stake_inference*(
    totalStakeEstimate: uint64,
    measuredDensity: uint64,
    period: uint64,
    beta: uint64,
    slotActivationCoeff: uint64,
): uint64 =
  ## Next-epoch total-stake estimate from the observed block density.
  ## `beta` and `slotActivationCoeff` are `fixedPoint` scalars. Floors at 1.
  doAssert period > 0
  doAssert slotActivationCoeff > 0
  let
    precisionP = Precision.i128
    tseP = totalStakeEstimate.i128 * precisionP
    measuredP = measuredDensity.i128 * precisionP
    expectedP = period.i128 * slotActivationCoeff.i128
    errorP = tseP * (expectedP - measuredP) div expectedP
    correctionP = beta.i128 * errorP div precisionP
    newEstimateP = (tseP - correctionP) div precisionP
  if newEstimateP < One128:
    1'u64
  else:
    doAssert newEstimateP <= MaxUint64128, "total stake exceeds uint64"
    newEstimateP.truncate(uint64)

{.pop.}
