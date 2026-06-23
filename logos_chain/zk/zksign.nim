# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## ZkSig ledger seam: VK singleton + `verify` against `[pks; msg]` public-input
## vector + `zksignInput` builder that right-pads short pk lists. Prover-side
## helpers land here when local signing goes live.

{.push raises: [], gcsafe.}

import
  std/[algorithm, os],
  results,
  stew/arrayops,
  ./circuits,
  ./groth16/[vk_json, verifier],
  ../core/crypto/types

export VKey, FieldElement, ProofBytesLen, vk_json, results

const
  ZkSignMaxKeys* = 32
    ## Circuit-imposed hard cap on signers per proof. >32 → reject; 1..32 →
    ## right-pad with `ZeroSecretKeyPublicKey`.

type
  ZkSignLoadError* {.pure.} = enum
    VkFileMissing
    VkReadFailed
    VkInvalid
    VkAlreadyLoaded
    VkNotLoaded

  ZkSignVerifierInput* = object
    ## Public-input vector. Field order is positional in the circuit's IC —
    ## do not reorder.
    publicKeys*: array[ZkSignMaxKeys, FieldElement]
    msg*: FieldElement

# Singleton. `initVk` must run on the main thread at startup, before any
# worker thread is spawned. `verify` is read-only and safe to call
# concurrently afterwards. `resetVkForTesting` is test-only — never call
# while workers are alive. The `cast(gcsafe)` blocks rely on this contract:
# under refc the singleton's seq is never mutated and never freed, so
# concurrent reads do no GC operations.
var zksignVk: Opt[VKey]

proc loadVk*(circuitsDir: string): Result[VKey, ZkSignLoadError] =
  ## Read + parse `<circuitsDir>/zksign/verification_key.json`.
  let path = zksignVerificationKeyPath(circuitsDir)
  if not fileExists(path):
    return err(VkFileMissing)
  let text =
    try:
      readFile(path)
    except IOError, OSError:
      return err(VkReadFailed)
  let vk = parseVk(text).valueOr:
    return err(VkInvalid)
  ok(vk)

proc initVk*(vk: VKey): Result[void, ZkSignLoadError] =
  ## Install the VK into the singleton. Reinitialisation returns
  ## `VkAlreadyLoaded` (use `resetVkForTesting` between test cases).
  {.cast(gcsafe).}:
    if zksignVk.isSome:
      return err(VkAlreadyLoaded)
    zksignVk = Opt.some(vk)
    ok()

proc loadAndInitVk*(circuitsDir: string): Result[void, ZkSignLoadError] =
  ## Composition-root helper: `loadVk` then `initVk`, once at startup.
  initVk(? loadVk(circuitsDir))

proc resetVkForTesting*() =
  ## Test-only: clear the singleton between cases. Not for production paths.
  {.cast(gcsafe).}:
    zksignVk = Opt.none(VKey)

proc zksignInput*(
    pks: openArray[ZkPublicKey], msg: FieldElement
): Result[ZkSignVerifierInput, cstring] =
  ## Build the verifier input from a variable-length pk seq and the message
  ## field element. Right-pads to `ZkSignMaxKeys` with `ZeroSecretKeyPublicKey`.
  if pks.len > ZkSignMaxKeys:
    return err("zksign: too many keys (max 32)")
  var input = ZkSignVerifierInput(msg: msg)
  input.publicKeys.fill(ZeroSecretKeyPublicKey)
  discard input.publicKeys.copyFrom(pks)
  ok(input)

proc verify*(
    proof: array[ProofBytesLen, byte], input: ZkSignVerifierInput
): Result[bool, ZkSignLoadError] =
  ## Verify against the installed singleton VK. `err(VkNotLoaded)` indicates
  ## a missing startup call, not adversarial input.
  {.cast(gcsafe).}:
    let vk = zksignVk.valueOr:
      return err(VkNotLoaded)
    var inputs: array[ZkSignMaxKeys + 1, FieldElement]
    inputs[0 ..< ZkSignMaxKeys] = input.publicKeys.toOpenArray(0, ZkSignMaxKeys - 1)
    inputs[ZkSignMaxKeys] = input.msg
    ok(verifyGroth16(vk, proof, inputs))

{.pop.}
