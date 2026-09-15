# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## snarkjs-shaped JSON on the prover path: rapidsnark's `proof.json` and
## `public.json` in, the 128-byte wire proof and typed public signals out,
## plus the decimal-string encoders that circuit input JSON uses.

{.push raises: [], gcsafe.}

import
  std/[json, sequtils],
  json_serialization,
  constantine/math/io/io_fields,
  groth16/bn128,
  ./[utils, verifier]

export utils, verifier

type
  ProofJson = object
    piA {.serializedFieldName: "pi_a".}: JsonG1
    piB {.serializedFieldName: "pi_b".}: JsonG2
    piC {.serializedFieldName: "pi_c".}: JsonG1
    protocol: string

  ProofPoints* = tuple[a: G1, b: G2, c: G1]

SnarkjsJson.useDefaultSerializationFor(ProofJson)

proc proofJsonToPoints*(text: string): Result[ProofPoints, JsonLoadError] =
  ## Parse snarkjs `proof.json` into affine points.
  let j =
    try:
      SnarkjsJson.decode(text, ProofJson)
    except SerializationError, IOError:
      return err(BadJson)
  if j.protocol != "groth16":
    return err(WrongProtocol)
  ok((? decodeJsonG1(j.piA), ? decodeJsonG2(j.piB), ? decodeJsonG1(j.piC)))

func toCompressedBytes*(points: ProofPoints): array[ProofBytesLen, byte] =
  ## `pi_a (G1) || pi_b (G2) || pi_c (G1)` in the arkworks compressed layout.
  let
    aBytes = unwrapComprG1(compressG1(points.a))
    bBytes = unwrapComprG2(compressG2(points.b))
    cBytes = unwrapComprG1(compressG1(points.c))
  var bytes: array[ProofBytesLen, byte]
  bytes[0 ..< 32] = aBytes.toOpenArray(0, 31)
  bytes[32 ..< 96] = bBytes.toOpenArray(0, 63)
  bytes[96 ..< 128] = cBytes.toOpenArray(0, 31)
  bytes

proc publicJsonToInputs*(
    text: string): Result[seq[FieldElement], JsonLoadError] =
  ## snarkjs `public.json` (flat array of decimal strings) → scalar field elements.
  let strs =
    try:
      SnarkjsJson.decode(text, seq[string])
    except SerializationError, IOError:
      return err(BadJson)
  var inputs = newSeqOfCap[FieldElement](strs.len)
  for s in strs:
    inputs.add(? frFromDecimal(s))
  ok(inputs)

func frDecimal*(x: FieldElement): string =
  ## Circuit input encoding of a field element: its decimal string.
  toDecimal(x)

func pathJson*(path: openArray[FieldElement]): JsonNode =
  %path.mapIt(frDecimal(it))

func selectorsJson*(selectors: openArray[bool]): JsonNode =
  ## Selector bits as "1" / "0" strings.
  %selectors.mapIt(if it: "1" else: "0")

{.pop.}
