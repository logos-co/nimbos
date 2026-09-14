# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## rapidsnark Groth16 prover and verifier wrapper.
##
## A `RapidsnarkProver` is created once per circuit from the zkey bytes and
## reused for every proof. rapidsnark keeps pointers into that buffer, so the
## bytes must stay alive and unmoved until `destroy`. It also creates its own
## thread pool at that point. Proving on one handle is not safe concurrently:
## callers serialise `prove` per handle.

{.push raises: [], gcsafe.}

import
  results,
  ./native_status

export results, native_status

type
  RapidsnarkError* {.pure.} = enum
    CreateFailed
    ProveFailed
    ShortBuffer
    InvalidWitnessLength
    VerifyError
    Unsupported

  RapidsnarkFailure* = NativeFailure[RapidsnarkError]

  RapidsnarkProver* = object
    ## Plain handle to a rapidsnark prover object. Copies are non-owning;
    ## exactly one owner calls `destroy`.
    handle: pointer
    proofBufSize: uint64
    publicBufSize: uint64

  ProofJsonPair* = tuple[proofJson, publicJson: string]

func isNil*(p: RapidsnarkProver): bool =
  p.handle == nil

when defined(windows):
  proc create*(
      T: type RapidsnarkProver, zkey: openArray[byte]
  ): Result[RapidsnarkProver, RapidsnarkFailure] =
    ## Stub: no rapidsnark archive links on this platform.
    err(RapidsnarkFailure(kind: RapidsnarkError.Unsupported))

  proc destroy*(p: var RapidsnarkProver) =
    p.handle = nil

  proc prove*(
      p: RapidsnarkProver, wtns: openArray[byte]
  ): Result[ProofJsonPair, RapidsnarkFailure] =
    err(RapidsnarkFailure(kind: RapidsnarkError.Unsupported))

  proc verifyJson*(
      proofJson, publicJson, vkJson: string
  ): Result[bool, RapidsnarkFailure] =
    err(RapidsnarkFailure(kind: RapidsnarkError.Unsupported))
else:
  import ../native_libs

  func failure(kind: RapidsnarkError, message: NativeMessage): RapidsnarkFailure =
    RapidsnarkFailure(kind: kind, message: message)

  proc create*(
      T: type RapidsnarkProver, zkey: openArray[byte]
  ): Result[RapidsnarkProver, RapidsnarkFailure] =
    ## Parse the zkey once. rapidsnark keeps pointers into `zkey`, so pass a
    ## shared-heap buffer that stays at that address until `destroy`.
    var message: NativeMessage
    if zkey.len == 0:
      return err(failure(RapidsnarkError.CreateFailed, message))
    var
      publicSize: culonglong
      proofSize: culonglong
      handle: pointer
    let zkeyPtr = unsafeAddr zkey[0]
    if groth16PublicSizeForZkeyBuf(
        zkeyPtr, culonglong(zkey.len), addr publicSize,
        cast[cstring](addr message[0]), culonglong(MessageLen)) != ProverOk:
      return err(failure(RapidsnarkError.CreateFailed, message))
    groth16ProofSize(addr proofSize)
    if groth16ProverCreate(
        addr handle, zkeyPtr, culonglong(zkey.len),
        cast[cstring](addr message[0]), culonglong(MessageLen)) != ProverOk:
      return err(failure(RapidsnarkError.CreateFailed, message))
    ok(RapidsnarkProver(
      handle: handle,
      proofBufSize: uint64(proofSize),
      publicBufSize: uint64(publicSize)))

  proc destroy*(p: var RapidsnarkProver) =
    ## Release the prover object. Safe to call more than once.
    if p.handle != nil:
      groth16ProverDestroy(p.handle)
      p.handle = nil

  proc proveOnce(
      p: RapidsnarkProver, wtns: openArray[byte],
      proofBuf, publicBuf: var string,
      message: var NativeMessage): cint =
    # The C side writes `len` bytes plus a NUL and reports `len`.
    var
      proofSize = culonglong(proofBuf.len)
      publicSize = culonglong(publicBuf.len)
    let code = groth16ProverProve(
      p.handle, unsafeAddr wtns[0], culonglong(wtns.len),
      cstring(proofBuf), addr proofSize,
      cstring(publicBuf), addr publicSize,
      cast[cstring](addr message[0]), culonglong(MessageLen))
    if code == ProverOk:
      proofBuf.setLen(int(proofSize))
      publicBuf.setLen(int(publicSize))
    elif code == ProverShortBuffer:
      # Required sizes, NUL included.
      proofBuf = newString(int(proofSize))
      publicBuf = newString(int(publicSize))
    code

  proc prove*(
      p: RapidsnarkProver, wtns: openArray[byte]
  ): Result[ProofJsonPair, RapidsnarkFailure] =
    ## Prove a `.wtns` buffer. Returns rapidsnark's proof JSON and
    ## public-signals JSON. Output strings are allocated on the calling
    ## thread. Not safe to call concurrently on one handle.
    var message: NativeMessage
    if p.handle == nil or wtns.len == 0:
      return err(failure(RapidsnarkError.ProveFailed, message))
    var
      proofBuf = newString(int(p.proofBufSize) + 1)
      publicBuf = newString(int(p.publicBufSize) + 1)
      code = proveOnce(p, wtns, proofBuf, publicBuf, message)
    if code == ProverShortBuffer:
      code = proveOnce(p, wtns, proofBuf, publicBuf, message)
    if code == ProverOk:
      return ok((proofBuf, publicBuf))
    let kind =
      if code == ProverInvalidWitnessLength: RapidsnarkError.InvalidWitnessLength
      elif code == ProverShortBuffer: RapidsnarkError.ShortBuffer
      else: RapidsnarkError.ProveFailed
    err(failure(kind, message))

  proc verifyJson*(
      proofJson, publicJson, vkJson: string
  ): Result[bool, RapidsnarkFailure] =
    ## rapidsnark's own verifier on snarkjs-shaped JSON. `ok(false)` is a
    ## rejected proof; `err` means the inputs could not be parsed.
    var message: NativeMessage
    let code = groth16Verify(
      cstring(proofJson), cstring(publicJson), cstring(vkJson),
      cast[cstring](addr message[0]), culong(MessageLen))
    if code == VerifierValidProof:
      ok(true)
    elif code == VerifierInvalidProof:
      ok(false)
    else:
      err(failure(RapidsnarkError.VerifyError, message))

{.pop.}
