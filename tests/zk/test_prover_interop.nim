# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Acceptance of Nim-made proofs by the reference toolchain: the rapidsnark
## verifier in-process and the bundled `verifier` binary, and the reverse
## check that the committed reference proofs still pass both verifiers.

{.push raises: [].}
{.used.}

import
  std/[os, osproc],
  unittest2,
  chronos,
  stew/io2,
  ../../logos_chain/zk/groth16/rapidsnark,
  ./prover_helpers

proc vkText(c: Circuit): string =
  readText(verificationKeyPath(testCircuitsDir, c))

proc inputFor(c: Circuit): ProveInput =
  case c
  of Circuit.Pol: ProveInput(circuit: Circuit.Pol, polInput: polFixtureInput())
  of Circuit.Poq:
    ProveInput(circuit: Circuit.Poq, poqInput: poqCoreFixtureInput(poqCoreFixtureIndex()))
  of Circuit.Poc: ProveInput(circuit: Circuit.Poc, pocInput: pocFixtureInput())
  of Circuit.Signature:
    ProveInput(circuit: Circuit.Signature, zksignInput: zksignFixtureInput())

proc proveJson(input: ProveInput): ProofJsonPair =
  ## Nim proof → snarkjs-shaped JSON, through the wire bytes and back.
  let o =
    try:
      (waitFor testProver().prove(input)).expect("prove " & $input.circuit)
    except CancelledError:
      raiseAssert "prove cancelled"
  # Recover affine points from the 128-byte form so the JSON round-trips the
  # exact bytes the network would carry.
  let points = proofBytesToPoints(o.proof).expect("wire bytes decompress")
  (pointsToProofJson(points), signalsToPublicJson(o.signals))

proc runBundledVerifier(c: Circuit, proofJson, publicJson: string): int =
  ## Exit code of `<bundle>/verifier vk public proof`, or -1 if absent.
  let verifier = testCircuitsDir / "verifier"
  if not fileExists(verifier):
    return -1
  let dir = uniqueTmpDir("interop_" & $c)
  createPath(dir).expect("temp dir")
  defer:
    try:
      os.removeDir(dir)
    except OSError:
      discard
  let
    proofPath = dir / "proof.json"
    publicPath = dir / "public.json"
  io2.writeFile(proofPath, proofJson).expect("write proof")
  io2.writeFile(publicPath, publicJson).expect("write public")
  try:
    execCmdEx(quoteShellCommand(
      [verifier, verificationKeyPath(testCircuitsDir, c), publicPath, proofPath])).exitCode
  except OSError, IOError:
    -1

suite "zk/prover — interop with the reference toolchain":
  for c in Circuit:
    test "rapidsnark verifier accepts a Nim proof (" & $c & ")":
      let (proofJson, publicJson) = proveJson(inputFor(c))
      check accepts(verifyJson(proofJson, publicJson, vkText(c)))
      let code = runBundledVerifier(c, proofJson, publicJson)
      if code == -1:
        skip()
      else:
        check code == 0

  test "rapidsnark verifier rejects tampered public signals":
    let (proofJson, publicJson) =
      proveJson(ProveInput(circuit: Circuit.Poc, pocInput: pocFixtureInput()))
    var signals = publicJsonToInputs(publicJson).expect("public")
    signals[1] = fr("12345")
    check rejects(verifyJson(proofJson, signalsToPublicJson(signals), vkText(Circuit.Poc)))

  test "committed reference proofs pass both verifiers":
    installFixtureVks()
    for c in [Circuit.Pol, Circuit.Poc, Circuit.Signature]:
      let
        proofJson = readText(fixtureDir(c) / "proof.json")
        publicJson = readText(fixtureDir(c) / "public.json")
      check accepts(verifyJson(proofJson, publicJson, vkText(c)))
      let
        bytes = proofJsonToBytes(proofJson).expect("bytes")
        signals = publicJsonToInputs(publicJson).expect("public")
      let accepted =
        case c
        of Circuit.Pol: pol.verify(bytes, polVerifierInput(signals).expect("9"))
        of Circuit.Poc: poc.verify(bytes, pocVerifierInput(signals).expect("3"))
        else: zksign.verify(bytes, zksignVerifierInput(signals).expect("33"))
      check accepts(accepted)

{.pop.}
