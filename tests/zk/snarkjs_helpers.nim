# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Test-only parsers for snarkjs `proof.json` / `public.json` artefacts. Both
## are produced by the snarkjs prover; our on-wire format for proofs is the
## 128-byte compressed form, so production code never parses these JSONs.
## Tests use them to feed canonical fixtures (logos-blockchain test resources)
## through `verifyGroth16` and `pol.verify`.

{.push raises: [].}

import
  json_serialization,
  stew/io2,
  groth16/bn128,
  ../../logos_chain/zk/groth16/[utils, verifier]

export utils, verifier

type
  ProofJson* = object
    piA* {.serializedFieldName: "pi_a".}: JsonG1
    piB* {.serializedFieldName: "pi_b".}: JsonG2
    piC* {.serializedFieldName: "pi_c".}: JsonG1
    protocol*: string

SnarkjsJson.useDefaultSerializationFor(ProofJson)

proc proofJsonToBytes*(
    text: string): Result[array[ProofBytesLen, byte], JsonLoadError] =
  ## Parse snarkjs proof.json → uncompressed G1/G2 → vendor `compressG1/G2`
  ## → 128-byte on-wire form that `verifyGroth16` consumes.
  let j =
    try:
      SnarkjsJson.decode(text, ProofJson)
    except SerializationError, IOError:
      return err(BadJson)
  let
    piA = ? decodeJsonG1(j.piA)
    piB = ? decodeJsonG2(j.piB)
    piC = ? decodeJsonG1(j.piC)
  var bytes: array[ProofBytesLen, byte]
  let
    aBytes = unwrapComprG1(compressG1(piA))
    bBytes = unwrapComprG2(compressG2(piB))
    cBytes = unwrapComprG1(compressG1(piC))
  for i in 0 ..< 32: bytes[i] = aBytes[i]
  for i in 0 ..< 64: bytes[32 + i] = bBytes[i]
  for i in 0 ..< 32: bytes[96 + i] = cBytes[i]
  ok(bytes)

proc publicJsonToInputs*(
    text: string): Result[seq[FieldElement], JsonLoadError] =
  ## Parse snarkjs public.json (flat array of decimal strings) → seq of scalar
  ## field elements ready to pass to `verifyGroth16`.
  let strs =
    try:
      SnarkjsJson.decode(text, seq[string])
    except SerializationError, IOError:
      return err(BadJson)
  var inputs = newSeqOfCap[FieldElement](strs.len)
  for s in strs:
    inputs.add(? frFromDecimal(s))
  ok(inputs)

{.pop.}
