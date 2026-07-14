# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  stint,
  unittest2,
  ../../logos_chain/zk/pol_lottery,
  ../../logos_chain/zk/poseidon2/hasher

func fr(hex: string): FieldElement {.raises: [ValueError].} =
  frFromBytesLE(UInt256.fromHex(hex).toBytesLE).expect("below BN254 order")

template checkPinnedConstants(fDen: uint64, t0Hex, t1Hex: string) =
  # At total stake 1, t₀ = ⌊T₀/1⌋ = T₀ and t₁ = p − ⌊T₁/1⌋ — directly
  # checkable against the spec-appendix hex.
  let
    pMinusT1 = Bn254POrder - UInt256.fromHex(t1Hex)
    values = computeLotteryValues(
      NonNegativeRatio(num: 1, den: fDen), 1).expect("supported f")
  check:
    values.t0 == fr(t0Hex)
    values.t1 == frFromBytesLE(pMinusT1.toBytesLE).expect("below order")

suite "zk/pol_lottery":
  test "lottery values for f = 1/30, total stake 1000":
    let values = computeLotteryValues(
      NonNegativeRatio(num: 1, den: 30), 1000).expect("supported f")
    check:
      values.t0 == fr(
        "0x6b83fe55f9383508b9bbe2d335e8e78d9c133ce0554b4f251b0ca3b6be8c")
      values.t1 == fr(
        "0x30644e7269c19af80558c2b75767747a6fa9f2beb0e87df2e51121184e5e6c17")

  test "f = 1/10 constants reproduce at total stake 1":
    checkPinnedConstants(
      10,
      "0x5193d04d01fb16d1b9c55677fc83950d1cf88207f4a5756431fde6db9ab1768",
      "0x44c2a290c72d4dc7d6e514a4b9683cc6e7c15e64f0f59482ec7d3f5906784a")

  test "f = 1/20 constants reproduce at total stake 1":
    checkPinnedConstants(
      20,
      "0x27b6fe27507c9b4c92e52e804ac89cdfa0b6c31ea2ff88ed3cd63792906e352",
      "0x104bfd09ebdd01fb0bbbf222248a8a067df6f05cf20eb1b17ec2a9284e6a0f")

  test "unsupported f is rejected":
    check computeLotteryValues(NonNegativeRatio(num: 2, den: 30), 1000).isErr

{.pop.}
