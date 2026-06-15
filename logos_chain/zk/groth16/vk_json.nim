# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Snarkjs `verification_key.json` schema and conversion to a nim-groth16 `VKey`.

{.push raises: [], gcsafe.}

import
  json_serialization,
  groth16/[bn128, zkey_types],
  ./utils

export VKey, SpecPoints, VerifierPoints, JsonLoadError, utils

type
  VerificationKeyJson* = object
    protocol*: string
    curve*: string
    alpha1* {.serializedFieldName: "vk_alpha_1".}: JsonG1
    beta2* {.serializedFieldName: "vk_beta_2".}: JsonG2
    gamma2* {.serializedFieldName: "vk_gamma_2".}: JsonG2
    delta2* {.serializedFieldName: "vk_delta_2".}: JsonG2
    ic* {.serializedFieldName: "IC".}: seq[JsonG1]

SnarkjsJson.useDefaultSerializationFor(VerificationKeyJson)

func toVKey*(j: VerificationKeyJson): Result[VKey, JsonLoadError] =
  ## Validate protocol/curve tags, decode all points, precompute `alphaBeta`.
  # `beta1`/`delta1` stay at zero: snarkjs JSON omits them and the vendor
  # verifier never reads them. A canary test in `tests/zk/groth16/test_verifier`
  # asserts this invariant.
  if j.protocol != "groth16":
    return err(WrongProtocol)
  if j.curve != "bn128":
    return err(WrongCurve)

  let
    alpha1 = ? decodeJsonG1(j.alpha1)
    beta2 = ? decodeJsonG2(j.beta2)
    gamma2 = ? decodeJsonG2(j.gamma2)
    delta2 = ? decodeJsonG2(j.delta2)

  var ic = newSeqOfCap[G1](j.ic.len)
  for raw in j.ic:
    ic.add(? decodeJsonG1(raw))

  ok(VKey(
    curve: "bn128",
    spec: SpecPoints(
      alpha1: alpha1,
      beta1: default(G1),
      beta2: beta2,
      gamma2: gamma2,
      delta1: default(G1),
      delta2: delta2,
      alphaBeta: pairing(alpha1, beta2),
    ),
    vpoints: VerifierPoints(pointsIC: ic),
  ))

proc parseVerificationKeyJson*(
    text: string): Result[VerificationKeyJson, JsonLoadError] =
  ## Decode snarkjs JSON text into the raw schema, no point validation.
  try:
    ok(SnarkjsJson.decode(text, VerificationKeyJson))
  except SerializationError, IOError:
    err(BadJson)

proc parseVk*(text: string): Result[VKey, JsonLoadError] =
  ## Decode snarkjs JSON text and build a verifier-ready `VKey`.
  toVKey(? parseVerificationKeyJson(text))

{.pop.}
