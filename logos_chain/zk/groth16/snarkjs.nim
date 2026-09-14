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
  std/[json, options, sequtils],
  json_serialization,
  constantine/math/io/io_fields,
  constantine/math/extension_fields/towers,
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

func proofBytesToPoints*(
    bytes: array[ProofBytesLen, byte]): Result[ProofPoints, cstring] =
  ## 128-byte wire proof → affine points (`err` on a point that does not
  ## decompress).
  let
    a = uncompressG1(ComprG1(sliceArr[32](bytes, 0)))
    b = uncompressG2(ComprG2(sliceArr[64](bytes, 32)))
    c = uncompressG1(ComprG1(sliceArr[32](bytes, 96)))
  if a.isNone or b.isNone or c.isNone:
    return err("proof bytes do not decompress")
  ok((a.get, b.get, c.get))

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

proc proofJsonToBytes*(
    text: string): Result[array[ProofBytesLen, byte], JsonLoadError] =
  ## snarkjs `proof.json` → 128-byte on-wire form that `verifyGroth16` consumes.
  ok(toCompressedBytes(? proofJsonToPoints(text)))

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

func g1Json(p: G1): JsonNode =
  %[toDecimal(p.x), toDecimal(p.y), "1"]

func g2Json(p: G2): JsonNode =
  %[
    [toDecimal(p.x.c0), toDecimal(p.x.c1)],
    [toDecimal(p.y.c0), toDecimal(p.y.c1)],
    ["1", "0"],
  ]

func pointsToProofJson*(points: ProofPoints): string =
  ## Affine points → snarkjs `proof.json` text (as rapidsnark emits it).
  $(%*{
    "pi_a": g1Json(points.a),
    "pi_b": g2Json(points.b),
    "pi_c": g1Json(points.c),
    "protocol": "groth16",
  })

func signalsToPublicJson*(signals: openArray[FieldElement]): string =
  ## Field elements → snarkjs `public.json` text.
  $(%signals.mapIt(toDecimal(it)))

func frDecimal*(x: FieldElement): string =
  ## Circuit input encoding of a field element: its decimal string.
  toDecimal(x)

func pathJson*(path: openArray[FieldElement]): JsonNode =
  %path.mapIt(frDecimal(it))

func selectorsJson*(selectors: openArray[bool]): JsonNode =
  ## Selector bits as "1" / "0" strings.
  %selectors.mapIt(if it: "1" else: "0")

{.pop.}
