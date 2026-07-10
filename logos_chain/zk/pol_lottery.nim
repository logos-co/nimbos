# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  results, stint,
  ./poseidon2/hasher

from ../core/utils import NonNegativeRatio

export results, NonNegativeRatio

const
  ## BN254 scalar field order.
  Bn254POrder = UInt256.fromHex(
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")

  ## Precomputed (t₀_constant, t₁_constant) per supported `f`, as pinned in
  ## the PoL spec appendix (`cryptarchia-proof-of-leadership.md` §Lottery
  ## Approximation): t₀_constant = ⌊p·(−ln(1−f))⌋, t₁_constant = ⌊p·ln²(1−f)/2⌋,
  ## derived offline at 512-bit precision. A zero entry means the constants
  ## for that `f` are not derived yet and `computeLotteryValues` rejects it.
  LotteryConstantsTable = [
    # f = 1/30 (mainnet)
    (fNum: 1'u64, fDen: 30'u64,
     t0: UInt256.fromHex(
       "0x1a3fb997fd5838f2a1585ee090a95c88129ab25cc4d2e2d28f1a95f81d85465"),
     t1: UInt256.fromHex(
       "0x71e790b4199113a9a00298d823c5716ddac764a110a45fe3b770bbb3e8a57")),
    # f = 1/20 (devnet) — derived with the spec-appendix formulas at 250
    # decimal digits (> 512-bit); the same derivation reproduces the pinned
    # 1/30 and 1/10 constants bit-for-bit.
    (fNum: 1'u64, fDen: 20'u64,
     t0: UInt256.fromHex(
       "0x27b6fe27507c9b4c92e52e804ac89cdfa0b6c31ea2ff88ed3cd63792906e352"),
     t1: UInt256.fromHex(
       "0x104bfd09ebdd01fb0bbbf222248a8a067df6f05cf20eb1b17ec2a9284e6a0f")),
    # f = 1/10 (standalone / e2e)
    (fNum: 1'u64, fDen: 10'u64,
     t0: UInt256.fromHex(
       "0x5193d04d01fb16d1b9c55677fc83950d1cf88207f4a5756431fde6db9ab1768"),
     t1: UInt256.fromHex(
       "0x44c2a290c72d4dc7d6e514a4b9683cc6e7c15e64f0f59482ec7d3f5906784a")),
  ]

func toFieldElement(v: UInt256): FieldElement =
  ## Requires `v` < the BN254 scalar order; holds for both lottery values by
  ## construction (t₀ ≤ t₀_constant < p, and t₁ = p − x with 0 < x ≤ p).
  frFromBytesLE(v.toBytesLE).expect("value below BN254 order")

func computeLotteryValues*(
    f: NonNegativeRatio, totalStake: uint64,
): Result[tuple[t0, t1: FieldElement], cstring] =
  ## Lottery threshold coefficients for the epoch:
  ##   t₀ = ⌊t₀_constant / totalStake⌋
  ##   t₁ = p − ⌊t₁_constant / totalStake²⌋
  ## 256-bit integer division only, per the PoL spec.
  doAssert totalStake > 0
  for entry in LotteryConstantsTable:
    if entry.fNum == f.num and entry.fDen == f.den:
      if entry.t0.isZero:
        return err(cstring"lottery constants not yet derived for this f")
      let
        stake = totalStake.u256
        t0 = entry.t0 div stake
        t1 = Bn254POrder - entry.t1 div (stake * stake)
      return ok((t0: t0.toFieldElement, t1: t1.toFieldElement))
  err(cstring"unsupported slot activation coefficient f")

{.pop.}
