# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Proof of Leadership: VK singleton + `verify`. Prover-side helpers (zkey,
## witness-gen) land here when consensus participation goes live.

{.push raises: [], gcsafe.}

import
  std/os,
  results,
  ./circuits,
  ./groth16/[vk_json, verifier]

export VKey, FieldElement, ProofBytesLen, vk_json, results

type
  PolLoadError* {.pure.} = enum
    VkFileMissing
    VkReadFailed
    VkInvalid
    VkAlreadyLoaded
    VkNotLoaded

  PolVerifierInput* = object
    ## PoL public-input vector. Field order is positional in the circuit's IC
    ## — do not reorder.
    entropyContribution*: FieldElement
    slotNumber*: FieldElement
    epochNonce*: FieldElement
    lottery0*: FieldElement
    lottery1*: FieldElement
    agedRoot*: FieldElement
    latestRoot*: FieldElement
    leaderPk1*: FieldElement
    leaderPk2*: FieldElement

# Singleton. `initVk` must run on the main thread at startup, before any
# worker thread is spawned. `verify` is read-only and safe to call
# concurrently afterwards. `resetVkForTesting` is test-only — never call
# while workers are alive. The `cast(gcsafe)` blocks in init/verify rely on
# this contract: under refc the singleton's seq is never mutated and never
# freed, so concurrent reads do no GC operations.
var polVk: Opt[VKey]

proc loadVk*(circuitsDir: string): Result[VKey, PolLoadError] =
  ## Read + parse `<circuitsDir>/pol/verification_key.json`.
  let path = polVerificationKeyPath(circuitsDir)
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

proc initVk*(vk: VKey): Result[void, PolLoadError] =
  ## Install the VK into the singleton. Reinitialisation returns
  ## `VkAlreadyLoaded` (use `resetVkForTesting` between test cases).
  {.cast(gcsafe).}:
    if polVk.isSome:
      return err(VkAlreadyLoaded)
    polVk = Opt.some(vk)
    ok()

proc loadAndInitVk*(circuitsDir: string): Result[void, PolLoadError] =
  ## Composition-root helper: `loadVk` then `initVk`, once at startup.
  initVk(? loadVk(circuitsDir))

proc resetVkForTesting*() =
  ## Test-only: clear the singleton between cases. Not for production paths.
  {.cast(gcsafe).}:
    polVk = Opt.none(VKey)

proc verify*(
    proof: array[ProofBytesLen, byte],
    input: PolVerifierInput): Result[bool, PolLoadError] =
  ## Verify against the installed singleton VK. `err(VkNotLoaded)` indicates
  ## a missing startup call, not adversarial input.
  {.cast(gcsafe).}:
    let vk = polVk.valueOr:
      return err(VkNotLoaded)
    ok(verifyGroth16(
      vk,
      proof,
      [
        input.entropyContribution,
        input.slotNumber,
        input.epochNonce,
        input.lottery0,
        input.lottery1,
        input.agedRoot,
        input.latestRoot,
        input.leaderPk1,
        input.leaderPk2,
      ],
    ))

{.pop.}
