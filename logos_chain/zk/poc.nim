# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Proof of Claim: VK singleton + `verify`. Prover-side helpers (zkey,
## witness-gen) land here when leader-claim proving goes live.

{.push raises: [], gcsafe.}

import
  ./[circuits, util]

export util

type
  PocLoadError* = VkLoadError

  PocVerifierInput* = object
    ## PoC public-input vector. Field order is positional in the circuit's IC
    ## — do not reorder. Matches snarkjs `public.json` / `poc.circom` output:
    ## `[voucher_nullifier, mantle_tx_hash, voucher_root]`.
    voucherNullifier*: FieldElement
    mantleTxHashFr*: FieldElement
    voucherRoot*: FieldElement

# Singleton. See `util` for the threading / GC-safety contract.
var pocVk: Opt[VKey]

proc loadVk*(circuitsDir: string): Result[VKey, PocLoadError] =
  ## Read + parse `<circuitsDir>/poc/verification_key.json`.
  loadVkFromPath(pocVerificationKeyPath(circuitsDir))

proc initVk*(vk: VKey): Result[void, PocLoadError] =
  ## Install the VK into the singleton. Reinitialisation returns
  ## `VkAlreadyLoaded` (use `resetVkForTesting` between test cases).
  {.cast(gcsafe).}:
    installVk(pocVk, vk)

proc loadAndInitVk*(circuitsDir: string): Result[void, PocLoadError] =
  ## Composition-root helper: `loadVk` then `initVk`, once at startup.
  initVk(? loadVk(circuitsDir))

proc resetVkForTesting*() =
  ## Test-only: clear the singleton between cases. Not for production paths.
  {.cast(gcsafe).}:
    pocVk.reset()

proc verify*(
    proof: array[ProofBytesLen, byte], input: PocVerifierInput
): Result[bool, PocLoadError] =
  ## Verify against the installed singleton VK. `err(VkNotLoaded)` indicates
  ## a missing startup call, not adversarial input.
  {.cast(gcsafe).}:
    let vk = pocVk.valueOr:
      return err(VkNotLoaded)
    ok(verifyGroth16(
      vk,
      proof,
      [
        input.voucherNullifier,
        input.mantleTxHashFr,
        input.voucherRoot,
      ],
    ))

{.pop.}
