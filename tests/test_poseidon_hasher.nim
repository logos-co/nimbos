# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import unittest2

import constantine/math/[arithmetic, io/io_bigints]
import poseidon2/types                   # B, F, zero, one, two

import ../logos_chain/zk/poseidon2/hasher

# Reference values cross-checked against logos-blockchain/zk/poseidon2/src/hasher.rs.
# We go BigInt -> fromBig instead of F.fromDecimal because constantine's FF
# fromDecimal is mis-declared raises:[] and won't compile under strict effect
# tracking — constantine's own tests use this same workaround.
suite "Poseidon2Hasher (BN254)":
  test "digest([0])":
    let expected = F.fromBig(B.fromDecimal(
      "14440562208246903332530876912784724937356723424375796042690034647976142142243"))
    check Poseidon2Hasher.digest([zero]) == expected

  test "digest([1])":
    let expected = F.fromBig(B.fromDecimal(
      "13955187255749411516377601857453481686854514827536340092448578824571923228920"))
    check Poseidon2Hasher.digest([one]) == expected

  test "digest([2])":
    let expected = F.fromBig(B.fromDecimal(
      "9632004710537414903275898870712812796867229507472840228295932832943785232633"))
    check Poseidon2Hasher.digest([two]) == expected

  test "digest([0, 1, 2])":
    let expected = F.fromBig(B.fromDecimal(
      "21739021971472524335152491270920095773040444510968189350907442466992269802900"))
    check Poseidon2Hasher.digest([zero, one, two]) == expected
