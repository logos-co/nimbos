# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Test-side snarkjs codec: the production module plus the directions only
## tests need (wire bytes → points → JSON), for feeding committed fixtures
## through the verifiers and Nim proofs through the reference toolchain.

{.push raises: [].}

import
  std/[json, sequtils],
  constantine/math/io/io_fields,
  constantine/math/extension_fields/towers,
  groth16/bn128,
  ../../logos_chain/zk/groth16/snarkjs

export snarkjs

func proofBytesToPoints*(
    bytes: array[ProofBytesLen, byte]): Result[ProofPoints, cstring] =
  ## 128-byte wire proof → affine points (`err` on a point that does not
  ## decompress).
  let
    a = decompress(ComprG1(sliceArr[32](bytes, 0))).valueOr:
      return err("proof bytes do not decompress")
    b = decompress(ComprG2(sliceArr[64](bytes, 32))).valueOr:
      return err("proof bytes do not decompress")
    c = decompress(ComprG1(sliceArr[32](bytes, 96))).valueOr:
      return err("proof bytes do not decompress")
  ok((a, b, c))

proc proofJsonToBytes*(
    text: string): Result[array[ProofBytesLen, byte], JsonLoadError] =
  ## snarkjs `proof.json` → 128-byte on-wire form that `verifyGroth16` consumes.
  ok(toCompressedBytes(? proofJsonToPoints(text)))

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

{.pop.}
