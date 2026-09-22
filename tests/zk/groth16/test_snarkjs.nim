# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  constantine/math/arithmetic,
  ../../../logos_chain/zk/groth16/snarkjs

const
  # BN254 scalar field modulus minus one: the largest canonical value.
  FrMaxDecimal =
    "21888242871839275222246405745257275088548364400416034343698204186575808495616"

func fr(decimal: string): FieldElement =
  frFromDecimal(decimal).expect("test decimal is a field element")

suite "zk/groth16/snarkjs — frDecimal":
  test "zero is \"0\", not an empty string":
    check frDecimal(fr("0")) == "0"

  test "small values carry no leading zeros":
    check frDecimal(fr("1")) == "1"
    check frDecimal(fr("10")) == "10"
    check frDecimal(fr("12345")) == "12345"

  test "the largest field element round-trips":
    check frDecimal(fr(FrMaxDecimal)) == FrMaxDecimal

  test "round-trips through frFromDecimal":
    for s in ["7", "4638531576864525781488466586415560847030933032030532999162151560076355183707"]:
      check bool(frFromDecimal(frDecimal(fr(s))).expect("decodes") == fr(s))

{.pop.}
