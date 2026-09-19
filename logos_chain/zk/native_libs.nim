# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Raw C bindings and link flags for the prebuilt prover libraries: the
## circuit witness generators from the logos-blockchain-circuits bundle and
## the rapidsnark Groth16 prover. Wrappers live in `witness_gen` and
## `groth16/rapidsnark`; nothing here is called directly by other modules.
##
## This is the only module with `passL`, so the archive order on the link
## line is fixed: consumers (`lib<circuit>`, `librapidsnark`) before providers
## (`libfr`, `libfq`, `libgmp`). GNU ld resolves archives left to right.
##
## The link roots default to space-free symlinks that `make deps` refreshes
## under `build/`; the user data dir never appears on a linker line (the macOS
## default contains a space). `-d:lbcRootDir=…` / `-d:rapidsnarkDir=…` override.
##
## No archive exists for Windows; every binding is absent there and the
## wrappers compile as stubs.

{.push raises: [], gcsafe.}

import
  std/os,
  ./groth16/native_status

const
  repoRoot = currentSourcePath.parentDir.parentDir.parentDir
  lbcRootDir {.strdefine.} = repoRoot / "build" / "circuits-bundle"
  rapidsnarkDir {.strdefine.} = repoRoot / "build" / "rapidsnark"

when not defined(windows):
  const
    linkSearch =
      "\"-L" & lbcRootDir / "pol" & "\" " &
      "\"-L" & lbcRootDir / "poq" & "\" " &
      "\"-L" & lbcRootDir / "poc" & "\" " &
      "\"-L" & lbcRootDir / "signature" & "\" " &
      "\"-L" & lbcRootDir / "lib" & "\" " &
      "\"-L" & rapidsnarkDir / "lib" & "\" "
    # `-L<bundle>/lib` precedes `-L<rapidsnark>/lib`, so `-lgmp` resolves to
    # the bundle's GMP. Both archives ship one; only one may be linked.
    linkLibs = "-lpol -lpoq -lpoc -lsignature -lrapidsnark -lfr -lfq -lgmp"

  {.passl: linkSearch & linkLibs.}
  when defined(macosx):
    {.passl: "-lc++".}
  else:
    {.passl: "-lstdc++ -lpthread".}

  type
    # ABI mirrors of <bundle>/<circuit>/include/types.hpp. The header uses
    # `bool` without <stdbool.h> and its helpers are `static inline`, so it
    # cannot be included from C; the layouts are declared here instead.
    Bytes* = object
      data*: ptr UncheckedArray[uint8]
      size*: csize_t

    StatusCode* {.size: sizeof(cint).} = enum
      Ok = 0
      DynError = 1
      InvalidInput = 2
      OutOfMemory = 3

    Status* = object
      ## Returned by value (260 bytes).
      code*: StatusCode
      message*: NativeMessage

    WitnessInput* = object
      dat*: Bytes    # `ConstBytes` in the header; the C side only reads it
      inputsJson*: cstring

  proc polGenerateWitness*(input: ptr WitnessInput, output: ptr Bytes): Status
    {.importc: "pol_generate_witness", cdecl.}
  proc poqGenerateWitness*(input: ptr WitnessInput, output: ptr Bytes): Status
    {.importc: "poq_generate_witness", cdecl.}
  proc pocGenerateWitness*(input: ptr WitnessInput, output: ptr Bytes): Status
    {.importc: "poc_generate_witness", cdecl.}
  proc signatureGenerateWitness*(input: ptr WitnessInput, output: ptr Bytes): Status
    {.importc: "signature_generate_witness", cdecl.}

  proc cFree*(p: pointer) {.importc: "free", header: "<stdlib.h>".}
    ## The witness buffer is `malloc`ed by the C side; `free_bytes` in
    ## `types.hpp` is `static inline` and cannot be linked.

  # https://github.com/iden3/rapidsnark/blob/v0.0.8/src/prover.h
  # https://github.com/iden3/rapidsnark/blob/v0.0.8/src/verifier.h
  const
    ProverOk* = 0.cint
    ProverError* = 1.cint
    ProverShortBuffer* = 2.cint
    ProverInvalidWitnessLength* = 3.cint
    VerifierValidProof* = 0.cint
    VerifierInvalidProof* = 1.cint
    VerifierError* = 2.cint

  proc groth16ProofSize*(size: ptr culonglong)
    {.importc: "groth16_proof_size", cdecl.}
  proc groth16PublicSizeForZkeyBuf*(
      zkey: pointer, zkeySize: culonglong, publicSize: ptr culonglong,
      err: cstring, errMax: culonglong): cint
    {.importc: "groth16_public_size_for_zkey_buf", cdecl.}
  proc groth16ProverCreate*(
      obj: ptr pointer, zkey: pointer, zkeySize: culonglong,
      err: cstring, errMax: culonglong): cint
    {.importc: "groth16_prover_create", cdecl.}
  proc groth16ProverProve*(
      obj: pointer, wtns: pointer, wtnsSize: culonglong,
      proofBuf: cstring, proofSize: ptr culonglong,
      publicBuf: cstring, publicSize: ptr culonglong,
      err: cstring, errMax: culonglong): cint
    {.importc: "groth16_prover_prove", cdecl.}
  proc groth16ProverDestroy*(obj: pointer)
    {.importc: "groth16_prover_destroy", cdecl.}
  proc groth16Verify*(
      proof, inputs, vk: cstring, err: cstring, errMax: culong): cint
    {.importc: "groth16_verify", cdecl.}

{.pop.}
