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

suite "zk/pol_lottery":
  test "lottery values for f = 1/30, total stake 1000":
    let values = computeLotteryValues(
      NonNegativeRatio(num: 1, den: 30), 1000).expect("supported f")
    check:
      values.t0 == fr(
        "0x6b83fe55f9383508b9bbe2d335e8e78d9c133ce0554b4f251b0ca3b6be8c")
      values.t1 == fr(
        "0x30644e7269c19af80558c2b75767747a6fa9f2beb0e87df2e51121184e5e6c17")

  test "total stake 1 reproduces the pinned constants":
    # t₀ = ⌊T₀/1⌋ = T₀ and t₁ = p − ⌊T₁/1⌋, directly checkable against the
    # spec-appendix hex.
    let
      pMinusT1 = UInt256.fromHex(
        "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001") -
        UInt256.fromHex(
          "0x44c2a290c72d4dc7d6e514a4b9683cc6e7c15e64f0f59482ec7d3f5906784a")
      values = computeLotteryValues(
        NonNegativeRatio(num: 1, den: 10), 1).expect("supported f")
    check:
      values.t0 == fr(
        "0x5193d04d01fb16d1b9c55677fc83950d1cf88207f4a5756431fde6db9ab1768")
      values.t1 == frFromBytesLE(pMinusT1.toBytesLE).expect("below order")

  test "unsupported f is rejected":
    check computeLotteryValues(NonNegativeRatio(num: 2, den: 30), 1000).isErr

  test "f = 1/20 constants reproduce at total stake 1":
    let
      pMinusT1 = UInt256.fromHex(
        "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001") -
        UInt256.fromHex(
          "0x104bfd09ebdd01fb0bbbf222248a8a067df6f05cf20eb1b17ec2a9284e6a0f")
      values = computeLotteryValues(
        NonNegativeRatio(num: 1, den: 20), 1).expect("supported f")
    check:
      values.t0 == fr(
        "0x27b6fe27507c9b4c92e52e804ac89cdfa0b6c31ea2ff88ed3cd63792906e352")
      values.t1 == frFromBytesLE(pMinusT1.toBytesLE).expect("below order")

{.pop.}
