# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Proof of Quota: VK singleton + `verify`, plus the prover-side witness
## input and its circuit JSON encoding.

{.push raises: [], gcsafe.}

import
  std/json,
  ./[circuits, merkle_path, util],
  ./groth16/snarkjs

export util, merkle_path

const
  PoqPublicSignals* = 12
  CoreTreeHeight* = 20
    ## Height of the core zk-id registry tree the blend branch proves against.

type
  PoqLoadError* = VkLoadError

  PoqVerifierInput* = object
    ## PoQ public-input vector in the circuit's IC order. Do not reorder.
    # Output first, then inputs in declaration order, not `public [...]`
    # order. That is why `pol_ledger_aged` sits sixth. Source at v0.5.6:
    # https://github.com/logos-blockchain/logos-blockchain-circuits/blob/07c439356435eb6a2f1f4a8daa973bd04bd0b088/blend/poq.circom
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

  PoqSelector* {.pure.} = enum
    ## Which branch of the circuit the proof takes.
    Core = 0
    Leader = 1
    Pow = 2

  PoqWitnessInput* = object
    ## Prover-side circuit inputs. The branch not selected keeps its fields
    ## zero; the circuit expects every signal to be present.
    coreRoot*: FieldElement
    polLedgerAged*: FieldElement
    polEpochNonce*: FieldElement
    polT0*: FieldElement
    polT1*: FieldElement
    coreQuota*: uint64
    leaderQuota*: uint64
    powQuota*: uint64
    kPartOne*: FieldElement
    kPartTwo*: FieldElement
    selector*: PoqSelector
    index*: uint64
    powBlendDifficulty*: FieldElement
    coreSk*: FieldElement
    corePath*: CircuitPath[CoreTreeHeight]
    polSlot*: uint64
    polNoteValue*: uint64
    polNoteTxHash*: FieldElement
    polNoteOutputNumber*: uint64
    polNoteidPath*: CircuitPath[TreeDepth]
    polSecretKey*: FieldElement
    powNonce*: FieldElement

func toInputsJson*(input: PoqWitnessInput): string =
  ## Witness-generator JSON with the circuit's input names.
  $(%*{
    "core_root": frDecimal(input.coreRoot),
    "pol_ledger_aged": frDecimal(input.polLedgerAged),
    "pol_epoch_nonce": frDecimal(input.polEpochNonce),
    "pol_t0": frDecimal(input.polT0),
    "pol_t1": frDecimal(input.polT1),
    "core_quota": $input.coreQuota,
    "leader_quota": $input.leaderQuota,
    "pow_quota": $input.powQuota,
    "K_part_one": frDecimal(input.kPartOne),
    "K_part_two": frDecimal(input.kPartTwo),
    "selector": $ord(input.selector),
    "index": $input.index,
    "pow_blend_difficulty": frDecimal(input.powBlendDifficulty),
    "core_sk": frDecimal(input.coreSk),
    "core_path": pathJson(input.corePath.siblings),
    "core_path_selectors": selectorsJson(input.corePath.selectors),
    "pol_sl": $input.polSlot,
    "pol_note_value": $input.polNoteValue,
    "pol_note_tx_hash": frDecimal(input.polNoteTxHash),
    "pol_note_output_number": $input.polNoteOutputNumber,
    "pol_noteid_path": pathJson(input.polNoteidPath.siblings),
    "pol_noteid_path_selectors": selectorsJson(input.polNoteidPath.selectors),
    "pol_secret_key": frDecimal(input.polSecretKey),
    "pow_nonce": frDecimal(input.powNonce),
  })

func poqVerifierInput*(
    signals: openArray[FieldElement]
): Result[PoqVerifierInput, cstring] =
  ## Typed view of the 12 public signals a proof carries.
  if signals.len != PoqPublicSignals:
    return err("poq: expected 12 public signals")
  ok(PoqVerifierInput(
    keyNullifier: signals[0],
    coreQuota: signals[1],
    leaderQuota: signals[2],
    coreRoot: signals[3],
    powQuota: signals[4],
    polLedgerAged: signals[5],
    kPartOne: signals[6],
    kPartTwo: signals[7],
    powBlendDifficulty: signals[8],
    polEpochNonce: signals[9],
    polT0: signals[10],
    polT1: signals[11]))

# Singleton. See `util` for the threading / GC-safety contract.
var poqVk: Opt[VKey]

proc loadVk*(circuitsDir: string): Result[VKey, PoqLoadError] =
  ## Read + parse `<circuitsDir>/poq/verification_key.json`.
  loadVkFromPath(verificationKeyPath(circuitsDir, Circuit.Poq))

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
