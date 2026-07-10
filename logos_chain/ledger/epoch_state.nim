# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  results,
  ../time/clock,
  ../zk/pol_lottery,
  ../zk/poseidon2/hasher,
  ./block_density,
  ./stake_inference,
  ./types

from stew/byteutils import toBytes
from ../core/mantle/primitives import slotToFr

export clock, types, hasher, block_density

type EpochState* = object
  ## The spec's Epoch State `(C_LEAD, η, D)` plus cached lottery coefficients.
  epoch*: EpochNumber
  nonce*: FieldElement ## η — frozen at nonceSnapshot(epoch)
  agedUtxoRoot*: FieldElement ## C_LEAD — frozen at stakeDistributionSnapshot(epoch)
  totalStake*: uint64 ## D — inferred, density-adjusted
  lottery0*: FieldElement ## t₀ for `totalStake`
  lottery1*: FieldElement ## t₁ for `totalStake`

let EpochNonceV1: FieldElement =
  # Nonce-chain domain separator, decoded once at module init; reading it
  # makes the nonce helpers procs.
  frFromBytesLE("EPOCH_NONCE_V1".toBytes).expect("14 bytes < order")

func withLottery(
    state: EpochState, totalStake: uint64,
    values: tuple[t0, t1: FieldElement],
): EpochState =
  var next = state
  next.totalStake = totalStake
  next.lottery0 = values.t0
  next.lottery1 = values.t1
  next

func withLottery*(
    state: EpochState, totalStake: uint64, f: NonNegativeRatio,
): Result[EpochState, LedgerError] =
  ## Copy of `state` with `totalStake` and freshly derived (t₀, t₁).
  let values = computeLotteryValues(f, totalStake).valueOr:
    return err(UnsupportedLotteryF)
  ok(state.withLottery(totalStake, values))

func genesisEpochState*(
    epoch: EpochNumber,
    genesisNonce: FieldElement,
    genesisRoot: FieldElement,
    genesisStake: uint64,
    f: NonNegativeRatio,
): Result[EpochState, LedgerError] =
  ## Seed state for epoch 0 (active) or epoch 1 (next) at chain start.
  EpochState(
    epoch: epoch, nonce: genesisNonce, agedUtxoRoot: genesisRoot
  ).withLottery(genesisStake, f)

proc accumulateNonce*(
    prevNonce: FieldElement,
    entropyContribution: FieldElement,
    slot: SlotNumber,
): FieldElement =
  ## One step of the nonce chain:
  ## `η' = zkHASH(EPOCH_NONCE_V1 ‖ η ‖ ρ_LEAD ‖ Fr(slot))`.
  Poseidon2Hasher.digest(
    [EpochNonceV1, prevNonce, entropyContribution, slotToFr(slot)])

func updateFromLedger*(
    state: EpochState,
    runningNonce: FieldElement,
    latestRoot: FieldElement,
    lastAppliedSlot: SlotNumber,
    s: EpochSchedule,
): EpochState =
  ## Chase-and-freeze of the next-epoch snapshots: each follows the running
  ## value (pre-block) while strictly before its snapshot slot, then freezes.
  var next = state
  if lastAppliedSlot < nonceSnapshot(state.epoch, s):
    next.nonce = runningNonce
  if lastAppliedSlot < stakeDistributionSnapshot(state.epoch, s):
    next.agedUtxoRoot = latestRoot
  next

type EpochTracker* = object
  ## Per-fork epoch bookkeeping carried in each block's ledger state.
  nonce*: FieldElement ## running nonce — evolves with every block, never freezes
  lastAppliedSlot*: SlotNumber
  activeEpoch*: EpochState ## governs the current epoch's lottery
  nextEpoch*: EpochState ## being chased/frozen for epoch + 1
  blockDensity*: BlockDensity

func genesisEpochTracker*(
    genesisNonce, genesisRoot: FieldElement,
    genesisStake: uint64,
    cfg: LedgerConfig,
): Result[EpochTracker, LedgerError] =
  ## Chain-start bookkeeping: epoch-0 and epoch-1 states both seeded from
  ## the genesis values, density window over epoch 0's first two phases.
  let epoch0 = ?genesisEpochState(
    0, genesisNonce, genesisRoot, genesisStake, cfg.slotActivationCoeff)
  var epoch1 = epoch0
  epoch1.epoch = 1
  ok(EpochTracker(
    nonce: genesisNonce,
    lastAppliedSlot: 0,
    activeEpoch: epoch0,
    nextEpoch: epoch1,
    blockDensity: BlockDensity.init(0, cfg.epochSchedule)))

func rotate(
    t: EpochTracker, newEpoch: EpochNumber, latestRoot: FieldElement,
    cfg: LedgerConfig,
): Result[EpochTracker, LedgerError] =
  # Promote the buffered next-epoch state (or synthesize one from the
  # running values when whole epochs passed without a block — nothing was
  # snapshotted then), refresh D from the observed density plus one
  # zero-density correction per skipped epoch, reseed the next snapshot.
  let period = nonceContributionPeriod(cfg.epochSchedule)
  var stake = total_stake_inference(
    t.activeEpoch.totalStake, t.blockDensity.density, period,
    cfg.stakeInferenceLearningRate, cfg.slotActivationCoeff)
  for _ in (t.activeEpoch.epoch + 1) ..< newEpoch:
    stake = total_stake_inference(
      stake, 0, period, cfg.stakeInferenceLearningRate, cfg.slotActivationCoeff)
  let
    values = computeLotteryValues(cfg.slotActivationCoeff, stake).valueOr:
      return err(UnsupportedLotteryF)
    promoted =
      if newEpoch == t.activeEpoch.epoch + 1:
        t.nextEpoch
      else:
        EpochState(epoch: newEpoch, nonce: t.nonce, agedUtxoRoot: latestRoot)
  var next = t
  next.activeEpoch = promoted.withLottery(stake, values)
  next.nextEpoch = EpochState(
    epoch: newEpoch + 1, nonce: t.nonce, agedUtxoRoot: latestRoot
  ).withLottery(stake, values)
  next.blockDensity = BlockDensity.init(newEpoch, cfg.epochSchedule)
  ok(next)

func advanceEpochs*(
    t: EpochTracker, slot: SlotNumber, latestRoot: FieldElement,
    cfg: LedgerConfig,
): Result[EpochTracker, LedgerError] =
  ## Header pre-verification: slot monotonicity, next-epoch chase, rotation.
  ## Verify the proof against `result.activeEpoch`, then call `recordBlock`.
  if slot <= t.lastAppliedSlot:
    return err(InvalidSlot)
  var next = t
  next.nextEpoch = t.nextEpoch.updateFromLedger(
    t.nonce, latestRoot, t.lastAppliedSlot, cfg.epochSchedule)
  let newEpoch = slotToEpoch(slot, cfg.epochSchedule)
  if newEpoch > t.activeEpoch.epoch:
    next = ?next.rotate(newEpoch, latestRoot, cfg)
  doAssert next.activeEpoch.epoch == newEpoch, "rotation must land on the slot's epoch"
  ok(next)

proc recordBlock*(
    t: EpochTracker, slot: SlotNumber, entropyContribution: FieldElement,
): EpochTracker =
  ## Post-verification bookkeeping: roll the block's entropy into the
  ## running nonce, count density, advance the slot cursor.
  var next = t
  next.nonce = accumulateNonce(t.nonce, entropyContribution, slot)
  next.blockDensity = t.blockDensity.increment(slot)
  next.lastAppliedSlot = slot
  next

{.pop.}
