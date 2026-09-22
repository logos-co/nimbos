# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Proof of Claim: VK singleton + `verify`, plus the prover-side witness
## input and its circuit JSON encoding.

{.push raises: [], gcsafe.}

import
  std/json,
  ./[circuits, merkle_path, util],
  ./groth16/snarkjs

export util, merkle_path

const
  PocPublicSignals* = 3

type
  PocLoadError* = VkLoadError

  PocVerifierInput* = object
    ## PoC public-input vector. Field order is positional in the circuit's IC
    ## — do not reorder. Matches snarkjs `public.json` / `poc.circom` output:
    ## `[voucher_nullifier, mantle_tx_hash, voucher_root]`.
    voucherNullifier*: FieldElement
    mantleTxHashFr*: FieldElement
    voucherRoot*: FieldElement

  PocWitnessInput* = object
    ## Prover-side circuit inputs. The voucher path comes from `toCircuitPath`.
    voucherRoot*: FieldElement
    mantleTxHash*: FieldElement
    secretVoucher*: FieldElement
    voucherPath*: CircuitPath[TreeDepth]

func toInputsJson*(input: PocWitnessInput): string =
  ## Witness-generator JSON with the circuit's input names.
  $(%*{
    "voucher_root": frDecimal(input.voucherRoot),
    "mantle_tx_hash": frDecimal(input.mantleTxHash),
    "secret_voucher": frDecimal(input.secretVoucher),
    "voucher_merkle_path": pathJson(input.voucherPath.siblings),
    "voucher_merkle_path_selectors": selectorsJson(input.voucherPath.selectors),
  })

func pocVerifierInput*(
    signals: openArray[FieldElement]
): Result[PocVerifierInput, cstring] =
  ## Typed view of the 3 public signals a proof carries.
  if signals.len != PocPublicSignals:
    return err("poc: expected 3 public signals")
  ok(PocVerifierInput(
    voucherNullifier: signals[0],
    mantleTxHashFr: signals[1],
    voucherRoot: signals[2]))

# Singleton. See `util` for the threading / GC-safety contract.
var pocVk: Opt[VKey]

proc loadVk*(circuitsDir: string): Result[VKey, PocLoadError] =
  ## Read + parse `<circuitsDir>/poc/verification_key.json`.
  loadVkFromPath(verificationKeyPath(circuitsDir, Circuit.Poc))

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
