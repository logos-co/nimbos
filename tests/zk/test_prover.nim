# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## End-to-end `Prover.prove` for every circuit on the taskpool, checked with
## the Nim verifiers, plus the error paths a caller can hit.

{.push raises: [].}
{.used.}

import
  std/times,
  unittest2,
  chronos,
  taskpools,
  ../../logos_chain/core/crypto/types,
  ./prover_helpers

proc proveOk(input: ProveInput): ProveOutput =
  let r =
    try:
      waitFor testProver().prove(input)
    except CancelledError:
      raiseAssert "prove cancelled"
  r.expect("prove " & $input.circuit)

func tamper(proof: CompressedGroth16Proof): CompressedGroth16Proof =
  var tampered = proof
  tampered[5] = tampered[5] xor 0x01
  tampered

# Runs before any suite that touches the shared pool: `Taskpool.new`
# rebinds this thread's worker context, and a second pool created after
# the shared one would leave that context dangling once shut down.
suite "zk/prover — construction":
  test "Prover.new needs two threads":
    var pool =
      try:
        Taskpool.new(numThreads = 1)
      except CatchableError as exc:
        raiseAssert exc.msg
    check Prover.new(testCircuitsDir, pool).error == ProverInitError.PoolTooSmall
    pool.shutdown()

  test "Prover.new reports a missing proving key":
    let dir = uniqueTmpDir("prover_missing")
    check Prover.new(dir, testPool()).error == ProverInitError.ProvingKeyMissing

  test "close is idempotent and a closed prover refuses to prove":
    let p = Prover.new(testCircuitsDir, testPool()).expect("prover")
    p.close()
    p.close()
    let r =
      try:
        waitFor p.prove(ProveInput(circuit: Circuit.Signature, zksignInput: zksignFixtureInput()))
      except CancelledError:
        raiseAssert "cancelled"
    check r.error == ProveError.Closed

suite "zk/prover — prove and verify":
  setup:
    installFixtureVks()

  test "signature":
    let
      start = epochTime()
      o = proveOk(ProveInput(circuit: Circuit.Signature, zksignInput: zksignFixtureInput()))
    check epochTime() - start < 10.0
    check o.publicSignalCount == ZkSignPublicSignals
    check o.signals == fixtureSignals(Circuit.Signature)
    let input = zksignVerifierInput(o.signals).expect("33 signals")
    check accepts(zksign.verify(o.proof, input))
    check rejects(zksign.verify(tamper(o.proof), input))
    var mutated = input
    mutated.msg = fr("7")
    check rejects(zksign.verify(o.proof, mutated))

  test "signature: public keys match the derivation of the secret keys":
    let
      witness = zksignFixtureInput()
      o = proveOk(ProveInput(circuit: Circuit.Signature, zksignInput: witness))
    for i in 0 ..< ZkSignMaxKeys:
      check o.publicSignals[i] == zkPublicKeyFromSecret(witness.secretKeys[i])
    check o.publicSignals[1] == ZeroSecretKeyPublicKey

  test "pol":
    let o = proveOk(ProveInput(circuit: Circuit.Pol, polInput: polFixtureInput()))
    check o.publicSignalCount == PolPublicSignals
    check o.signals == fixtureSignals(Circuit.Pol)
    let input = polVerifierInput(o.signals).expect("9 signals")
    check accepts(pol.verify(o.proof, input))
    check rejects(pol.verify(tamper(o.proof), input))
    var mutated = input
    mutated.slotNumber = fr("136")
    check rejects(pol.verify(o.proof, mutated))

  test "poc":
    let o = proveOk(ProveInput(circuit: Circuit.Poc, pocInput: pocFixtureInput()))
    check o.publicSignalCount == PocPublicSignals
    check o.signals == fixtureSignals(Circuit.Poc)
    let input = pocVerifierInput(o.signals).expect("3 signals")
    check accepts(poc.verify(o.proof, input))
    check rejects(poc.verify(tamper(o.proof), input))

  test "poq (core branch)":
    let o = proveOk(ProveInput(
      circuit: Circuit.Poq, poqInput: poqCoreFixtureInput(PoqCoreFixtureIndex)))
    check o.publicSignalCount == PoqPublicSignals
    check o.signals == fixtureSignals(Circuit.Poq)
    let input = poqVerifierInput(o.signals).expect("12 signals")
    check accepts(poq.verify(o.proof, input))
    check rejects(poq.verify(tamper(o.proof), input))

  test "two proofs of one input differ and both verify":
    let
      a = proveOk(ProveInput(circuit: Circuit.Signature, zksignInput: zksignFixtureInput()))
      b = proveOk(ProveInput(circuit: Circuit.Signature, zksignInput: zksignFixtureInput()))
    check a.proof != b.proof
    let input = zksignVerifierInput(a.signals).expect("33 signals")
    check accepts(zksign.verify(a.proof, input))
    check accepts(zksign.verify(b.proof, input))

  test "concurrent callers are serialised and both succeed":
    let
      f1 = testProver().prove(ProveInput(circuit: Circuit.Signature, zksignInput: zksignFixtureInput()))
      f2 = testProver().prove(ProveInput(circuit: Circuit.Poc, pocInput: pocFixtureInput()))
      a = (try: waitFor f1 except CancelledError: raiseAssert "cancelled").expect("first")
      b = (try: waitFor f2 except CancelledError: raiseAssert "cancelled").expect("second")
    check accepts(zksign.verify(a.proof, zksignVerifierInput(a.signals).expect("33")))
    check accepts(poc.verify(b.proof, pocVerifierInput(b.signals).expect("3")))

{.pop.}
