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

const Precision* = 1000'u64 ## fixed-point scale — spec-pinned

func fixedPoint*(r: NonNegativeRatio): uint64 =
  ## `truncate(r × Precision)` computed exactly in integers.
  doAssert r.den > 0
  r.num * Precision div r.den

func total_stake_inference*(
    totalStakeEstimate: uint64,
    measuredDensity: uint64,
    period: uint64,
    beta: NonNegativeRatio,
    slotActivationCoeff: NonNegativeRatio,
): uint64 =
  ## Next-epoch total-stake estimate from the observed block density
  ## (`cryptarchia-total-stake-inference.md` §Algorithm). Floors at 1.
  doAssert period > 0
  doAssert slotActivationCoeff.num > 0
  let
    betaP = beta.fixedPoint
    fP = slotActivationCoeff.fixedPoint
    precisionP = Precision.i128
    tseP = totalStakeEstimate.i128 * precisionP
    measuredP = measuredDensity.i128 * precisionP
    expectedP = period.i128 * fP.i128
    errorP = tseP * (expectedP - measuredP) div expectedP
    correctionP = betaP.i128 * errorP div precisionP
    newEstimateP = (tseP - correctionP) div precisionP
  if newEstimateP < 1'u64.i128:
    1'u64
  else:
    doAssert newEstimateP <= uint64.high.i128, "total stake exceeds uint64"
    newEstimateP.truncate(uint64)

{.pop.}
