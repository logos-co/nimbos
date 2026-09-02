# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Proof of Quota: VK singleton + `verify`.

{.push raises: [], gcsafe.}

import
  ./[circuits, util]

export util

type
  PoqLoadError* = VkLoadError

  PoqVerifierInput* = object
    ## PoQ public-input vector. Field order is positional in the
    ## circuit's IC. Do not reorder: the spec pins the 12 signals.
    # The order is the output first, then the inputs in circuit
    # declaration order. It is not the `public [...]` clause order, which
    # is why `pol_ledger_aged` sits sixth.
    keyNullifier*: FieldElement
    coreQuota*: FieldElement
    leaderQuota*: FieldElement
    coreRoot*: FieldElement
    powQuota*: FieldElement
    polLedgerAged*: FieldElement
    kPartOne*: FieldElement
    kPartTwo*: FieldElement
    powBlendDifficulty*: FieldElement
    polEpochNonce*: FieldElement
    polT0*: FieldElement
    polT1*: FieldElement

# Singleton. See `util` for the threading / GC-safety contract.
var poqVk: Opt[VKey]

proc loadVk*(circuitsDir: string): Result[VKey, PoqLoadError] =
  ## Read + parse `<circuitsDir>/poq/verification_key.json`.
  loadVkFromPath(poqVerificationKeyPath(circuitsDir))

proc initVk*(vk: VKey): Result[void, PoqLoadError] =
  ## Install the VK into the singleton. Reinitialisation returns
  ## `VkAlreadyLoaded` (use `resetVkForTesting` between test cases).
  {.cast(gcsafe).}:
    installVk(poqVk, vk)

proc loadAndInitVk*(circuitsDir: string): Result[void, PoqLoadError] =
  ## Composition-root helper: `loadVk` then `initVk`, once at startup.
  initVk(? loadVk(circuitsDir))

proc resetVkForTesting*() =
  ## Test-only: clear the singleton between cases. Not for production paths.
  {.cast(gcsafe).}:
    poqVk.reset()

proc verify*(
    proof: array[ProofBytesLen, byte], input: PoqVerifierInput
): Result[bool, PoqLoadError] =
  ## Verify against the installed singleton VK. `err(VkNotLoaded)` indicates
  ## a missing startup call, not adversarial input.
  {.cast(gcsafe).}:
    let vk = poqVk.valueOr:
      return err(VkNotLoaded)
    ok(verifyGroth16(
      vk,
      proof,
      [
        input.keyNullifier,
        input.coreQuota,
        input.leaderQuota,
        input.coreRoot,
        input.powQuota,
        input.polLedgerAged,
        input.kPartOne,
        input.kPartTwo,
        input.powBlendDifficulty,
        input.polEpochNonce,
        input.polT0,
        input.polT1,
      ],
    ))

{.pop.}
