# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Generic Groth16/BN254 verifier wrapper. Decomposes the 128-byte compressed
## proof, applies the snarkjs constant-1 input prefix, traps vendor asserts.
## No per-circuit knowledge.

{.push raises: [], gcsafe.}

import
  std/options,
  groth16/[bn128, zkey_types],
  ../poseidon2/hasher

from groth16/prover import Proof
from groth16/verifier as vendor_verifier import verifyProof

export VKey, FieldElement

const
  G1CompressedBytes = 32
  G2CompressedBytes = 64
  ProofBytesLen* = G1CompressedBytes + G2CompressedBytes + G1CompressedBytes
    ## On-wire compressed proof: `pi_a (G1) || pi_b (G2) || pi_c (G1)`.

func sliceArr[N: static int](src: openArray[byte], offset: int): array[N, byte] =
  for i in 0 ..< N:
    result[i] = src[offset + i]

proc verifyGroth16*(
    vk: VKey,
    proofBytes: array[ProofBytesLen, byte],
    publicInputs: openArray[FieldElement]): bool =
  ## Verify a compressed Groth16 proof against `vk` + public inputs.
  ## Returns `false` on any failure path; no exception escapes.
  const
    PiAOffset = 0
    PiBOffset = G1CompressedBytes
    PiCOffset = G1CompressedBytes + G2CompressedBytes

  let
    piAOpt = uncompressG1(
      ComprG1(sliceArr[G1CompressedBytes](proofBytes, PiAOffset)))
    piBOpt = uncompressG2(
      ComprG2(sliceArr[G2CompressedBytes](proofBytes, PiBOffset)))
    piCOpt = uncompressG1(
      ComprG1(sliceArr[G1CompressedBytes](proofBytes, PiCOffset)))

  if piAOpt.isNone or piBOpt.isNone or piCOpt.isNone:
    return false

  # Snarkjs convention: IC[0] is the constant-1 variable; prepend `one`.
  var publicIO = newSeqOfCap[FieldElement](publicInputs.len + 1)
  publicIO.add(one)
  for fe in publicInputs:
    publicIO.add(fe)

  let proof = Proof(
    pi_a: piAOpt.get,
    pi_b: piBOpt.get,
    pi_c: piCOpt.get,
    publicIO: publicIO,
    curve: "bn128",
  )

  # `verifyProof` asserts on-curve and curve-string; our `uncompressG1`/`G2`
  # already pre-validate, but trap defects defensively.
  try:
    {.cast(gcsafe).}:
      verifyProof(vk, proof)
  except AssertionDefect:
    false

{.pop.}
