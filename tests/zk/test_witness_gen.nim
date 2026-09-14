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
  stew/endians2,
  ../../logos_chain/zk/witness_gen,
  ./prover_helpers

const
  # nVars from the zkey headers of bundle v0.5.6.
  SignatureVars = 7715
  PolVars = 20531
  PocVars = 8293
  PoqVars = 20168

proc datFor(c: Circuit): seq[byte] =
  readBundleFile(witnessDatPath(testCircuitsDir, c))

func signalsMatch(values: openArray[FieldElement], expected: seq[FieldElement]): bool =
  if values.len < expected.len + 1 or values[0] != one:
    return false
  for i, s in expected:
    if values[i + 1] != s:
      return false
  true

when not defined(windows):
  suite "zk/witness_gen — reference vectors":
    test "signature: sks = [1, 0 × 31] reproduces the fixture public signals":
      let values = witnessValues(Circuit.Signature, toInputsJson(zksignFixtureInput()))
      check values.len == SignatureVars
      check signalsMatch(values, fixtureSignals(Circuit.Signature))
      check values[33] == fr(ZkSignFixtureMsg)

    test "pol: reference test_full_flow inputs reproduce the fixture public signals":
      let values = witnessValues(Circuit.Pol, toInputsJson(polFixtureInput()))
      check values.len == PolVars
      check signalsMatch(values, fixtureSignals(Circuit.Pol))

    test "poc: sample.input.json reproduces the fixture public signals":
      let values = witnessValues(Circuit.Poc, toInputsJson(pocFixtureInput()))
      check values.len == PocVars
      check signalsMatch(values, fixtureSignals(Circuit.Poc))

    test "poq: core-branch fixture reproduces public_core.json":
      let values = witnessValues(
        Circuit.Poq, toInputsJson(poqCoreFixtureInput(poqCoreFixtureIndex())))
      check values.len == PoqVars
      check signalsMatch(values, fixtureSignals(Circuit.Poq))

    test "poq: a key index at the quota is rejected by the circuit":
      let r = generateWitness(Circuit.Poq, datFor(Circuit.Poq),
        toInputsJson(poqCoreFixtureInput(PoqCoreFixtureQuota)))
      check r.isErr

  suite "zk/witness_gen — error mapping":
    test "missing signal → InvalidInput":
      let r = generateWitness(Circuit.Signature, datFor(Circuit.Signature),
        """{"msg": "1"}""")
      check r.error.kind == WitnessGenError.InvalidInput
      check messageString(r.error.message).contains("inputs")

    test "malformed JSON → DynError":
      let r = generateWitness(Circuit.Signature, datFor(Circuit.Signature), "{not json")
      check r.error.kind == WitnessGenError.DynError

    test "inputs of another circuit → DynError (unknown signal)":
      # Correct .dat for the circuit; only the JSON is wrong. The C side
      # throws "Signal not found" (printed, not returned), which maps to
      # DynError.
      let r = generateWitness(Circuit.Signature, datFor(Circuit.Signature),
        toInputsJson(pocFixtureInput()))
      check r.error.kind == WitnessGenError.DynError

    test "empty .dat → InvalidInput":
      let r = generateWitness(Circuit.Signature, [], toInputsJson(zksignFixtureInput()))
      check r.error.kind == WitnessGenError.InvalidInput

suite "zk/witness_gen — wtns decoder":
  func header(nVars: uint32): seq[byte] =
    var bytes = @[byte 'w', byte 't', byte 'n', byte 's', 2, 0, 0, 0, 2, 0, 0, 0,
      1, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0]
    bytes.setLen(60)
    bytes.add(nVars.toBytesLE)
    bytes.add([byte 2, 0, 0, 0])
    bytes.add(uint64(32 * nVars).toBytesLE)
    bytes

  test "rejects a short buffer":
    check decodeWtns([byte 1, 2, 3]).error == WtnsDecodeError.TooShort

  test "rejects a bad magic":
    var bytes = header(1)
    bytes.setLen(76 + 32)
    bytes[0] = byte 'x'
    check decodeWtns(bytes).error == WtnsDecodeError.BadMagic

  test "rejects a length mismatch":
    var bytes = header(2)
    bytes.setLen(76 + 32)
    check decodeWtns(bytes).error == WtnsDecodeError.LengthMismatch

  test "rejects a value at or above the field order":
    var bytes = header(1)
    bytes.setLen(76 + 32)
    for i in 76 ..< 108:
      bytes[i] = 0xff
    check decodeWtns(bytes).error == WtnsDecodeError.ValueOutOfRange

  test "decodes a single zero value":
    var bytes = header(1)
    bytes.setLen(76 + 32)
    let values = decodeWtns(bytes).expect("decodes")
    check values.len == 1
    check values[0] == zero

{.pop.}
