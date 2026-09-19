# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Witness generation through the bundle FFI, checked against the public
## signals of the committed reference proofs. A witness starts with the
## constant 1, then the public signals in circom order.

{.push raises: [].}
{.used.}

import
  std/strutils,
  unittest2,
  ../../logos_chain/zk/witness_gen,
  ./prover_helpers

const
  # nVars from the zkey headers of bundle v0.5.6.
  SignatureVarsV056 = 7715
  PolVarsV056 = 20531
  PocVarsV056 = 8293
  PoqVarsV056 = 20168

func signalsMatch(values: openArray[FieldElement], expected: seq[FieldElement]): bool =
  if values.len < expected.len + 1 or values[0] != one:
    return false
  for i, s in expected:
    if values[i + 1] != s:
      return false
  true

suite "zk/witness_gen — reference vectors":
  test "signature: sks = [1, 0 × 31] reproduces the fixture public signals":
    let values = witnessValues(Circuit.Signature, toInputsJson(zksignFixtureInput()))
    check values.len == SignatureVarsV056
    check signalsMatch(values, fixtureSignals(Circuit.Signature))
    check values[33] == fr(ZkSignFixtureMsg)

  test "pol: reference test_full_flow inputs reproduce the fixture public signals":
    let values = witnessValues(Circuit.Pol, toInputsJson(polFixtureInput()))
    check values.len == PolVarsV056
    check signalsMatch(values, fixtureSignals(Circuit.Pol))

  test "poc: sample.input.json reproduces the fixture public signals":
    let values = witnessValues(Circuit.Poc, toInputsJson(pocFixtureInput()))
    check values.len == PocVarsV056
    check signalsMatch(values, fixtureSignals(Circuit.Poc))

  test "poq: core-branch fixture reproduces public_core.json":
    let values = witnessValues(
      Circuit.Poq, toInputsJson(poqCoreFixtureInput(PoqCoreFixtureIndex)))
    check values.len == PoqVarsV056
    check signalsMatch(values, fixtureSignals(Circuit.Poq))

  test "poq: a key index at the quota is rejected by the circuit":
    let r = generateWitness(Circuit.Poq,
      toInputsJson(poqCoreFixtureInput(PoqCoreFixtureQuota)))
    check r.isErr

suite "zk/witness_gen — error mapping":
  test "missing signal → InvalidInput":
    let r = generateWitness(Circuit.Signature, """{"msg": "1"}""")
    check r.error.kind == WitnessGenError.InvalidInput
    check messageString(r.error.message).contains("inputs")

  test "malformed JSON → DynError":
    let r = generateWitness(Circuit.Signature, "{not json")
    check r.error.kind == WitnessGenError.DynError

  test "inputs of another circuit → DynError (unknown signal)":
    # The C side throws "Signal not found" (printed, not returned), which
    # maps to DynError.
    let r = generateWitness(Circuit.Signature, toInputsJson(pocFixtureInput()))
    check r.error.kind == WitnessGenError.DynError

{.pop.}
