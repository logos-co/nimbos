# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Shared snarkjs JSON primitives: G1/G2 schemas, decimal-to-field decoders,
## lenient JSON flavor, and the shared error type.

{.push raises: [], gcsafe.}

import
  results,
  json_serialization,
  constantine/math/arithmetic,
  constantine/math/extension_fields/towers,
  constantine/math/io/io_bigints,
  constantine/named/properties_fields,
  groth16/bn128,
  ../poseidon2/hasher

export results, FieldElement

type
  JsonLoadError* {.pure.} = enum
    BadJson
    WrongProtocol
    WrongCurve
    BadFieldElement
    BadG1Point
    BadG2Point

  JsonG1* = array[3, string] ## `[x, y, "1"]`, decimal strings.
  JsonG2* = array[3, array[2, string]] ## `[[x0, x1], [y0, y1], ["1", "0"]]`.

# Lenient flavor: snarkjs JSON ships extras we don't declare (e.g. `nPublic`).
# `requireAllFields` stays true so missing-required-field errors still surface.
createJsonFlavor SnarkjsJson

func fpFromDecimal*(s: string): Result[Fp[BN254_Snarks], JsonLoadError] =
  ## Parse a decimal string into a BN254 base-field element.
  try:
    let big = BigInt[254].fromDecimal(s)
    var fp: Fp[BN254_Snarks]
    fp.fromBig(big)
    ok(fp)
  except CatchableError:
    err(BadFieldElement)

func fp2FromDecimal*(c0, c1: string): Result[Fp2[BN254_Snarks], JsonLoadError] =
  ## Parse two decimal strings into an Fp2 quadratic-extension element.
  let
    a = ? fpFromDecimal(c0)
    b = ? fpFromDecimal(c1)
  ok(mkFp2(a, b))

func frFromDecimal*(s: string): Result[FieldElement, JsonLoadError] =
  ## Parse a decimal string into a BN254 scalar-field element.
  try:
    let big = BigInt[254].fromDecimal(s)
    var fr: FieldElement
    fr.fromBig(big)
    ok(fr)
  except CatchableError:
    err(BadFieldElement)

func decodeJsonG1*(j: JsonG1): Result[G1, JsonLoadError] =
  ## Decode a snarkjs G1 triple to an on-curve affine point.
  # Curve-check here so we can use `unsafeMkG1` and avoid vendor `mkG1`'s assert.
  let
    x = ? fpFromDecimal(j[0])
    y = ? fpFromDecimal(j[1])
  if isZeroFp(x) and isZeroFp(y):
    return ok(infG1)
  if not checkCurveEqG1(x, y):
    return err(BadG1Point)
  ok(unsafeMkG1(x, y))

func decodeJsonG2*(j: JsonG2): Result[G2, JsonLoadError] =
  ## Decode a snarkjs G2 triple to an in-subgroup affine point.
  # Subgroup check (stricter than curve check); avoids vendor `mkG2`'s assert.
  let
    x = ? fp2FromDecimal(j[0][0], j[0][1])
    y = ? fp2FromDecimal(j[1][0], j[1][1])
  if isZeroFp2(x) and isZeroFp2(y):
    return ok(infG2)
  if not checkSubgroupG2(x, y):
    return err(BadG2Point)
  ok(unsafeMkG2(x, y))

{.pop.}
