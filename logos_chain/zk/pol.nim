# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Proof of Leadership: VK singleton + `verify`, plus the prover-side
## witness input and its circuit JSON encoding.

{.push raises: [], gcsafe.}

import
  std/json,
  ./[circuits, merkle_path, util],
  ./groth16/snarkjs

export util, merkle_path

const
  PolPublicSignals* = 9

type
  PolLoadError* = VkLoadError

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

  PolWitnessInput* = object
    ## Prover-side circuit inputs: the chain part (public) and the wallet
    ## part (private). Paths come from `toCircuitPath`.
    slotNumber*: uint64
    epochNonce*: FieldElement
    lottery0*: FieldElement
    lottery1*: FieldElement
    agedRoot*: FieldElement
    latestRoot*: FieldElement
    leaderPk1*: FieldElement
    leaderPk2*: FieldElement
    noteValue*: uint64
    noteTxHash*: FieldElement
    noteOutputNumber*: uint64
    agedPath*: CircuitPath[TreeDepth]
    latestPath*: CircuitPath[TreeDepth]
    secretKey*: FieldElement

func toInputsJson*(input: PolWitnessInput): string =
  ## Witness-generator JSON with the circuit's input names.
  $(%*{
    "sl": $input.slotNumber,
    "epoch_nonce": frDecimal(input.epochNonce),
    "t0": frDecimal(input.lottery0),
    "t1": frDecimal(input.lottery1),
    "ledger_aged": frDecimal(input.agedRoot),
    "ledger_latest": frDecimal(input.latestRoot),
    "P_lead_part_one": frDecimal(input.leaderPk1),
    "P_lead_part_two": frDecimal(input.leaderPk2),
    "v": $input.noteValue,
    "note_tx_hash": frDecimal(input.noteTxHash),
    "note_output_number": $input.noteOutputNumber,
    "noteid_aged_path": pathJson(input.agedPath.siblings),
    "noteid_aged_selectors": selectorsJson(input.agedPath.selectors),
    "noteid_latest_path": pathJson(input.latestPath.siblings),
    "noteid_latest_selectors": selectorsJson(input.latestPath.selectors),
    "secret_key": frDecimal(input.secretKey),
  })

func polVerifierInput*(
    signals: openArray[FieldElement]
): Result[PolVerifierInput, cstring] =
  ## Typed view of the 9 public signals a proof carries.
  if signals.len != PolPublicSignals:
    return err("pol: expected 9 public signals")
  ok(PolVerifierInput(
    entropyContribution: signals[0],
    slotNumber: signals[1],
    epochNonce: signals[2],
    lottery0: signals[3],
    lottery1: signals[4],
    agedRoot: signals[5],
    latestRoot: signals[6],
    leaderPk1: signals[7],
    leaderPk2: signals[8]))

# Singleton. See `util` for the threading / GC-safety contract.
var polVk: Opt[VKey]

proc loadVk*(circuitsDir: string): Result[VKey, PolLoadError] =
  ## Read + parse `<circuitsDir>/pol/verification_key.json`.
  loadVkFromPath(verificationKeyPath(circuitsDir, Circuit.Pol))

proc initVk*(vk: VKey): Result[void, PolLoadError] =
  ## Install the VK into the singleton. Reinitialisation returns
  ## `VkAlreadyLoaded` (use `resetVkForTesting` between test cases).
  {.cast(gcsafe).}:
    installVk(polVk, vk)

proc loadAndInitVk*(circuitsDir: string): Result[void, PolLoadError] =
  ## Composition-root helper: `loadVk` then `initVk`, once at startup.
  initVk(? loadVk(circuitsDir))

proc resetVkForTesting*() =
  ## Test-only: clear the singleton between cases. Not for production paths.
  {.cast(gcsafe).}:
    polVk.reset()

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
