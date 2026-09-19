# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## rapidsnark binding: prover object lifecycle, proving a witness from the
## bundle FFI, and the in-process verifier on snarkjs-shaped JSON.

{.push raises: [].}
{.used.}

import
  std/strutils,
  unittest2,
  ../../logos_chain/zk/witness_gen,
  ../../logos_chain/zk/groth16/rapidsnark,
  ./prover_helpers

proc witnessBytes(c: Circuit, json: string): seq[byte] =
  generateWitness(c, json).valueOr:
    raiseAssert "witness generation failed: " & $error.kind

suite "zk/groth16/rapidsnark — prover object":
  test "create parses the signature zkey and destroy is idempotent":
    let zkey = readBundleFile(provingKeyPath(testCircuitsDir, Circuit.Signature))
    var p = RapidsnarkProver.create(zkey).expect("create")
    check not p.isNil
    p.destroy()
    check p.isNil
    p.destroy()
    check p.isNil

  test "create rejects a buffer that is not a zkey":
    var garbage = newSeq[byte](100)
    let r = RapidsnarkProver.create(garbage)
    check r.error.kind == RapidsnarkError.CreateFailed

  test "prove on a destroyed handle fails cleanly":
    let zkey = readBundleFile(provingKeyPath(testCircuitsDir, Circuit.Signature))
    var p = RapidsnarkProver.create(zkey).expect("create")
    p.destroy()
    let r = p.prove(witnessBytes(Circuit.Signature, toInputsJson(zksignFixtureInput())))
    check r.error.kind == RapidsnarkError.ProveFailed

suite "zk/groth16/rapidsnark — prove and verify":
  let zkey = readBundleFile(provingKeyPath(testCircuitsDir, Circuit.Signature))
  var p = RapidsnarkProver.create(zkey).expect("create")
  let vkJson = readText(verificationKeyPath(testCircuitsDir, Circuit.Signature))

  test "proof JSON has the snarkjs shape and the fixture public signals":
    let jsons = p.prove(
      witnessBytes(Circuit.Signature, toInputsJson(zksignFixtureInput()))).expect("prove")
    check jsons.proofJson.contains("\"protocol\"")
    let points = proofJsonToPoints(jsons.proofJson)
    check points.isOk
    let signals = publicJsonToInputs(jsons.publicJson).expect("public parses")
    check signals == fixtureSignals(Circuit.Signature)

  test "the proof verifies in-process and through the Nim verifier":
    let jsons = p.prove(
      witnessBytes(Circuit.Signature, toInputsJson(zksignFixtureInput()))).expect("prove")
    check accepts(verifyJson(jsons.proofJson, jsons.publicJson, vkJson))
    installFixtureVks()
    let
      bytes = proofJsonToBytes(jsons.proofJson).expect("bytes")
      signals = publicJsonToInputs(jsons.publicJson).expect("public parses")
      input = zksignVerifierInput(signals).expect("33 signals")
    check accepts(zksign.verify(bytes, input))

  test "tampered public signals are rejected, garbage vk is an error":
    let jsons = p.prove(
      witnessBytes(Circuit.Signature, toInputsJson(zksignFixtureInput()))).expect("prove")
    var signals = publicJsonToInputs(jsons.publicJson).expect("public parses")
    signals[32] = fr("2")
    check rejects(verifyJson(jsons.proofJson, signalsToPublicJson(signals), vkJson))
    let bad = verifyJson(jsons.proofJson, jsons.publicJson, "{not json")
    check bad.error.kind == RapidsnarkError.VerifyError

  test "witness of another circuit → InvalidWitnessLength":
    let r = p.prove(witnessBytes(Circuit.Poc, toInputsJson(pocFixtureInput())))
    check r.error.kind == RapidsnarkError.InvalidWitnessLength

  test "truncated witness → ProveFailed":
    var wtns = witnessBytes(Circuit.Signature, toInputsJson(zksignFixtureInput()))
    wtns.setLen(wtns.len - 32)
    let r = p.prove(wtns)
    check r.error.kind in {RapidsnarkError.ProveFailed, RapidsnarkError.InvalidWitnessLength}

  test "two proofs of one witness differ and both verify":
    let
      wtns = witnessBytes(Circuit.Signature, toInputsJson(zksignFixtureInput()))
      a = p.prove(wtns).expect("prove")
      b = p.prove(wtns).expect("prove")
    check a.proofJson != b.proofJson
    check accepts(verifyJson(a.proofJson, a.publicJson, vkJson))
    check accepts(verifyJson(b.proofJson, b.publicJson, vkJson))

  p.destroy()

{.pop.}
