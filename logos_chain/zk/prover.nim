# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Groth16 prover for every circuit: witness generation through the bundle
## FFI, proving through rapidsnark, then the 128-byte wire form.
##
## Proving runs on a taskpool worker so the chronos loop stays responsive.
## Only plain values, pointers, and a thread signal cross the spawn;
## the caller preallocates the output on its async frame and the worker
## stores its status before firing the signal. Under refc nothing
## garbage-collected travels between threads.
##
## One proof runs at a time: rapidsnark shares one FFT object per prover
## handle and parallelises internally on its own thread pool. Roughly 35 MB
## of proving keys stay resident for the node's lifetime.

{.push raises: [], gcsafe.}

import
  std/[atomics, os],
  chronos, chronos/threadsync, chronicles, taskpools,
  stew/[assign2, io2],
  ./[circuits, poc, pol, poq, witness_gen, zksign],
  ./groth16/[rapidsnark, snarkjs],
  ../core/crypto/types

export circuits, poc, pol, poq, zksign, CompressedGroth16Proof

logScope: topics = "zk_prover"

const MaxPublicSignals = ZkSignPublicSignals
  ## Largest public-signal count across circuits (zksign: 32 keys + msg).

type
  ProveInput* = object
    case circuit*: Circuit
    of Circuit.Pol: polInput*: PolWitnessInput
    of Circuit.Poq: poqInput*: PoqWitnessInput
    of Circuit.Poc: pocInput*: PocWitnessInput
    of Circuit.Signature: zksignInput*: ZkSignWitnessInput

  ProveError* {.pure.} = enum
    WitnessGen
    ProverFailed
    ProofDecode
    PublicDecode
    Closed
    Unsupported

  ProveOutput* = object
    ## Preallocated by the caller; filled by the worker.
    ok*: Atomic[bool]
    proof*: CompressedGroth16Proof
    publicSignals*: array[MaxPublicSignals, FieldElement]
      ## Circom order: outputs first, then inputs in declaration order.
    publicSignalCount*: int
    error*: ProveError
    message*: NativeMessage
      ## Message from the native side; logged on the main thread.

  SharedBytes = object
    ## Bytes on the shared heap: a fixed address for the node's lifetime, so
    ## native code may keep pointers into them and workers may read them.
    data: ptr UncheckedArray[byte]
    len: int

  ProverKey = object
    zkey: SharedBytes   # rapidsnark keeps pointers into this buffer
    rs: RapidsnarkProver

  ProverInitError* {.pure.} = enum
    PoolTooSmall
    SignalCreateFailed
    ProvingKeyMissing
    ProvingKeyReadFailed
    ProvingKeyInvalid
    Unsupported

  Prover* = ref object
    keys: array[Circuit, ProverKey]
    pool: Taskpool
    signal: ThreadSignalPtr
    lock: AsyncLock

proc free(shared: var SharedBytes) =
  if shared.data != nil:
    deallocShared(shared.data)
    shared.data = nil
  shared.len = 0

proc loadShared(path: string): Opt[SharedBytes] =
  # Reads straight into the shared block: no transient Nim copy of the key.
  let handle = openFile(path, {OpenFlags.Read}).valueOr:
    return Opt.none(SharedBytes)
  defer: discard closeFile(handle)
  let size = getFileSize(handle).valueOr:
    return Opt.none(SharedBytes)
  var shared = SharedBytes(len: int(size))
  if shared.len > 0:
    shared.data = cast[ptr UncheckedArray[byte]](allocShared(shared.len))
    var filled = 0
    while filled < shared.len:
      let n = readFile(handle, shared.data.toOpenArray(filled, shared.len - 1)).valueOr:
        shared.free()
        return Opt.none(SharedBytes)
      if n == 0:
        shared.free()
        return Opt.none(SharedBytes)
      filled += int(n)
  Opt.some(shared)

template toOpenArray(shared: SharedBytes): openArray[byte] =
  shared.data.toOpenArray(0, shared.len - 1)

func signals*(output: ProveOutput): seq[FieldElement] =
  ## The public signals in circom order, as a fresh `seq`. Hot callers read
  ## `publicSignals` up to `publicSignalCount` directly.
  output.publicSignals[0 ..< output.publicSignalCount]

proc proveTask(
    rs: RapidsnarkProver,
    input: ptr ProveInput,
    output: ptr ProveOutput,
    signal: ThreadSignalPtr) {.nimcall, gcsafe, raises: [].} =
  # Every temporary here is allocated and freed on this worker. The status
  # store is the last write before the signal fires.
  var
    ok = false
    failure = ProveError.ProverFailed
    message: NativeMessage
  defer:
    output[].error = failure
    output[].message = message
    output[].ok.store(ok)
    discard signal.fireSync()

  block work:
    let json =
      case input[].circuit
      of Circuit.Pol: toInputsJson(input[].polInput)
      of Circuit.Poq: toInputsJson(input[].poqInput)
      of Circuit.Poc: toInputsJson(input[].pocInput)
      of Circuit.Signature: toInputsJson(input[].zksignInput)
    let wtns = generateWitness(input[].circuit, json).valueOr:
      failure =
        if error.kind == WitnessGenError.Unsupported: ProveError.Unsupported
        else: ProveError.WitnessGen
      message = error.message
      break work
    let jsons = rs.prove(wtns).valueOr:
      message = error.message
      break work
    let points = proofJsonToPoints(jsons.proofJson).valueOr:
      failure = ProveError.ProofDecode
      break work
    let signals = publicJsonToInputs(jsons.publicJson).valueOr:
      failure = ProveError.PublicDecode
      break work
    if signals.len > MaxPublicSignals:
      failure = ProveError.PublicDecode
      break work
    output[].proof = toCompressedBytes(points)
    assign(output[].publicSignals.toOpenArray(0, signals.high), signals)
    output[].publicSignalCount = signals.len
    ok = true

proc spawnProveTask(p: Prover, input: ptr ProveInput, output: ptr ProveOutput) =
  # Kept out of the async proc: `spawn` inside an `{.async.}` body does not
  # compile.
  let key = addr p.keys[input[].circuit]
  p.pool.spawn proveTask(key[].rs, input, output, p.signal)

proc loadKey(key: var ProverKey, circuitsDir: string, c: Circuit): Result[void, ProverInitError] =
  # Fills the slot in place: the rapidsnark object is created from the
  # buffer at its final address.
  key.zkey = loadShared(provingKeyPath(circuitsDir, c)).valueOr:
    return err(ProverInitError.ProvingKeyReadFailed)
  key.rs = RapidsnarkProver.create(key.zkey.toOpenArray).valueOr:
    if error.kind == RapidsnarkError.Unsupported:
      return err(ProverInitError.Unsupported)
    debug "proving key rejected", circuit = c, message = messageString(error.message)
    return err(ProverInitError.ProvingKeyInvalid)
  ok()

proc checkArtefacts(circuitsDir: string): Result[void, ProverInitError] =
  # Runs on every platform so a missing bundle is reported even where proving
  # is a stub.
  for c in Circuit:
    if not fileExists(provingKeyPath(circuitsDir, c)):
      return err(ProverInitError.ProvingKeyMissing)
  ok()

proc close*(p: Prover) =
  ## Release native objects, key buffers, and the signal. Idempotent. No
  ## proof may be in flight: shut the taskpool down first.
  for c in Circuit:
    p.keys[c].rs.destroy()
    p.keys[c].zkey.free()
  if p.signal != nil:
    discard p.signal.close()
    p.signal = nil

proc new*(
    T: type Prover, circuitsDir: string, pool: Taskpool
): Result[Prover, ProverInitError] =
  ## Load the four proving keys and witness data files and create one
  ## rapidsnark prover per circuit. `pool` needs a second thread: the worker
  ## fires the signal the main thread waits on.
  ? checkArtefacts(circuitsDir)
  when defined(windows):
    return err(ProverInitError.Unsupported)
  else:
    if pool.numThreads < 2:
      return err(ProverInitError.PoolTooSmall)
    let signal = ThreadSignalPtr.new().valueOr:
      return err(ProverInitError.SignalCreateFailed)
    let p = Prover(pool: pool, signal: signal, lock: newAsyncLock())
    for c in Circuit:
      loadKey(p.keys[c], circuitsDir, c).isOkOr:
        p.close()
        return err(error)
    ok(p)

proc prove*(
    p: Prover, input: ProveInput
): Future[Result[ProveOutput, ProveError]] {.async: (raises: [CancelledError]).} =
  ## Generate a proof on a taskpool worker. Serialised per prover. A nil
  ## prover (platforms without proving) reports `Unsupported`.
  if p.isNil:
    return err(ProveError.Unsupported)
  await p.lock.acquire()
  defer:
    try:
      p.lock.release()
    except AsyncLockError as exc:
      raiseAssert "prover lock release failed: " & exc.msg
  if p.signal == nil:
    return err(ProveError.Closed)

  var
    inp = input
    output: ProveOutput
  p.spawnProveTask(addr inp, addr output)
  # To support cancellation, we'd have to ensure the task we posted to taskpools
  # exits early - since we're not doing that, block cancellation attempts
  try:
    await noCancel p.signal.wait()
  except AsyncError as exc:
    # Since we initialized the signal, the OS or chronos is misbehaving. In any
    # case, it would mean the task is still running which would cause a memory
    # violation if we let it run - panic instead
    raiseAssert "Could not wait for signal, was it initialized? " & exc.msg

  if not output.ok.load():
    debug "proof generation failed",
      circuit = input.circuit, error = output.error,
      message = messageString(output.message)
    return err(output.error)
  ok(output)

{.pop.}
