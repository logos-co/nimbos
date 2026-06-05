# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/[os, strutils],
  unittest2,
  stew/io2,
  ../../../logos_chain/zk/groth16/vk_json,
  ../snarkjs_helpers

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  fixtureVk = testsDir / "../../fixtures/pol/verification_key.json"
  fixtureProof = testsDir / "../../fixtures/pol/proof.json"
  fixturePublic = testsDir / "../../fixtures/pol/public.json"

suite "zk/groth16/verifier":
  var
    vk: VKey
    proofBytes: array[ProofBytesLen, byte]
    publicInputs: seq[FieldElement]

  setup:
    let vkText = readAllChars(fixtureVk).valueOr:
      check false
      return
    let proofText = readAllChars(fixtureProof).valueOr:
      check false
      return
    let publicText = readAllChars(fixturePublic).valueOr:
      check false
      return
    vk = parseVk(vkText).valueOr:
      check false
      return
    proofBytes = proofJsonToBytes(proofText).valueOr:
      check false
      return
    publicInputs = publicJsonToInputs(publicText).valueOr:
      check false
      return

  test "accepts canonical PoL test vector":
    check verifyGroth16(vk, proofBytes, publicInputs)

  test "rejects bit-flipped proof":
    var bad = proofBytes
    bad[0] = bad[0] xor 0x01
    check not verifyGroth16(vk, bad, publicInputs)

  test "rejects mutated public input":
    var bad = publicInputs
    # Swap two entries — preserves length and validity, breaks the pairing equation.
    swap(bad[0], bad[1])
    check not verifyGroth16(vk, proofBytes, bad)

  test "rejects garbage proof bytes":
    var bytes: array[ProofBytesLen, byte]
    for i in 0 ..< ProofBytesLen:
      bytes[i] = byte(i)
    check not verifyGroth16(vk, bytes, publicInputs)

  test "Q1 canary — verify result unchanged with non-zero beta1/delta1":
    # Plan §7 Q1: vendor verifier doesn't read spec.beta1/spec.delta1. Bumping
    # them to a non-default G1 (we reuse alpha1) must not flip the verify result.
    # Catches future vendor changes that start consuming the G1 halves.
    var vkBumped = vk
    vkBumped.spec.beta1 = vk.spec.alpha1
    vkBumped.spec.delta1 = vk.spec.alpha1
    check verifyGroth16(vkBumped, proofBytes, publicInputs)

{.pop.}
