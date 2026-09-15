# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Circuit witness generation through the bundle's `lib<circuit>.a` FFI.
## Input is the circuit's `.dat` bytes plus a JSON object of decimal strings;
## output is the snarkjs `.wtns` container that rapidsnark consumes.
##
## The C side copies the first `.dat` it receives for a circuit into a
## process-wide cache and ignores later ones, without a size check. Every
## call for a circuit must therefore pass that circuit's own `.dat`; a wrong
## one reads out of bounds and corrupts all later proofs for the circuit.

{.push raises: [], gcsafe.}

import
  results,
  ./circuits,
  ./groth16/native_status

export results, native_status

type
  WitnessGenError* {.pure.} = enum
    InvalidInput
    DynError
    OutOfMemory
    EmptyOutput
    Unsupported

  WitnessGenFailure* = NativeFailure[WitnessGenError]

when defined(windows):
  # Proving is out of scope on Windows for now; the stub keeps the module and
  # its tests compiling there.
  proc generateWitness*(
      circuit: Circuit, dat: openArray[byte], inputsJson: string
  ): Result[seq[byte], WitnessGenFailure] =
    err(WitnessGenFailure(kind: WitnessGenError.Unsupported))
else:
  import ./native_libs

  func toError(code: StatusCode): WitnessGenError =
    # Callers check `Ok` first; the branch exists only for exhaustiveness.
    case code
    of StatusCode.InvalidInput: WitnessGenError.InvalidInput
    of StatusCode.DynError: WitnessGenError.DynError
    of StatusCode.OutOfMemory: WitnessGenError.OutOfMemory
    of StatusCode.Ok: WitnessGenError.DynError

  proc generateWitness*(
      circuit: Circuit, dat: openArray[byte], inputsJson: string
  ): Result[seq[byte], WitnessGenFailure] =
    ## Run the circuit's witness generator. `dat` must be the circuit's own
    ## `witness_generator.dat` bytes; `inputsJson` uses the circuit's input
    ## names with every value as a decimal string.
    if dat.len == 0:
      return err(WitnessGenFailure(kind: WitnessGenError.InvalidInput))
    var
      input = WitnessInput(
        dat: Bytes(
          data: cast[ptr UncheckedArray[uint8]](unsafeAddr dat[0]),
          size: csize_t(dat.len)),
        inputsJson: cstring(inputsJson))
      output: Bytes    # C requires `data == NULL` on entry
    let status =
      case circuit
      of Circuit.Pol: polGenerateWitness(addr input, addr output)
      of Circuit.Poq: poqGenerateWitness(addr input, addr output)
      of Circuit.Poc: pocGenerateWitness(addr input, addr output)
      of Circuit.Signature: signatureGenerateWitness(addr input, addr output)
    if status.code != StatusCode.Ok:
      return err(WitnessGenFailure(kind: toError(status.code), message: status.message))
    # A failed `malloc` reports Ok with an empty buffer.
    if output.data == nil or output.size == 0:
      return err(WitnessGenFailure(kind: WitnessGenError.EmptyOutput))
    # Copied into Nim-owned memory so the caller needs no manual free. The
    # extra copy is well under a millisecond against the proof that follows.
    var wtns = newSeq[byte](int(output.size))
    copyMem(addr wtns[0], output.data, wtns.len)
    cFree(output.data)
    ok(wtns)

{.pop.}
