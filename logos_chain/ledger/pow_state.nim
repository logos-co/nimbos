# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Proof-of-work reward state: the reward pool, the reward threshold, the
## acceptance window and the spent tickets.
## Spec: [Proof of Work v1.1.0](https://github.com/logos-co/logos-lips/blob/760f5ee6f27cdb0b7b4d2fc1c79a49831dfcba6a/docs/blockchain/raw/proof-of-work.md)
## Spec: [Mantle Specification v1.19.0, CLAIM_POW_REWARD](https://github.com/logos-co/logos-lips/blob/bd1ca2c881ae94606d4ab23af1255fd922e85dd6/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md#claim_pow_reward)

{.push raises: [], gcsafe.}

import
  stint,
  ../core/mantle/[gas, operations, primitives, proofs],
  ../utils/hash_trie_map,
  ../zk/poseidon2/hasher,
  ./[types, zksig_verify]

type PowState* = object
  ## Proof-of-work reward state carried in each block's ledger state.
  rewardPool*: TokenValue
  epochReward*: TokenValue ## reward per claim, fixed for the epoch
  pendingRefill*: TokenValue ## fee share of the open epoch
  difficultyReward*: UInt256 ## reward threshold, retargeted after each block
  nullifiers*: HashTrieMap[FieldElement, SlotNumber] ## ticket to anchor slot
  blockSlots*: HashTrieMap[Hash32, SlotNumber] ## applied blocks in the window
  claimsInBlock: uint64 ## claims applied in the open block

func compute_epoch_pow_reward(
    pool: TokenValue, cfg: PowRewardConfig): TokenValue =
  ## Returns the reward per claim for one epoch, a fixed fraction of the pool.
  # Config load guarantees `rate_num <= rate_den`, and the other factors of
  # the divisor are 1 or more. So the reward is at most the pool and fits
  # uint64.
  (pool.u256 * cfg.rateNum.u256 div cfg.rateDenominator).truncate(uint64)

func init*(_: typedesc[PowState], cfg: PowRewardConfig): PowState =
  ## The genesis state: the seeded pool and the reward derived from it.
  PowState(
    rewardPool: cfg.genesisPool,
    epochReward: compute_epoch_pow_reward(cfg.genesisPool, cfg),
    difficultyReward: cfg.rewardTargetCap)

func feeShare*(fees: GasCost, cfg: PowRewardConfig): GasCost =
  ## The part of one block's fees that goes to the reward pool.
  # Config load guarantees `powShare <= shareDen`, so the share is at most
  # `fees` and fits uint64.
  (u128(fees) * u128(cfg.powShare) div u128(cfg.shareDen)).truncate(uint64)

func addPendingRefill*(
    s: sink PowState, refill: GasCost): Result[PowState, LedgerError] =
  ## Adds one block's fee share to the open epoch's refill.
  s.pendingRefill = s.pendingRefill.checkedAdd(refill).valueOr:
    return err(BalanceOutOfRange)
  ok(s)

func startEpoch*(
    s: sink PowState, cfg: PowRewardConfig): Result[PowState, LedgerError] =
  ## Moves the refill into the pool and recomputes the reward per claim.
  s.rewardPool = s.rewardPool.checkedAdd(s.pendingRefill).valueOr:
    return err(BalanceOutOfRange)
  s.pendingRefill = 0
  s.epochReward = compute_epoch_pow_reward(s.rewardPool, cfg)
  ok(s)

func compute_new_reward_difficulty*(
    claimsInBlock: uint64, currentTarget: UInt256,
    cfg: PowRewardConfig): UInt256 =
  ## The reward threshold for the next block, from this block's claim count.
  # The integers have 512 bits. `target * current * precision` is below
  # 2^64 * 2^254 * 2^64 = 2^382, and `demand` is below 2^129. So no value
  # overflows.
  template precision: untyped = cfg.emaSmoothingPrecision
  template factor: untyped = cfg.emaSmoothingFactor
  template target: untyped = cfg.targetClaimsPerBlock
  let
    demand = max(
      stuint(1, 512),
      (precision - factor) * stuint(claimsInBlock, 512) + factor * target)
    newTarget = target * stuint(currentTarget, 512) * precision div demand
  # The cap is at most p - 1, so the conversion to 256 bits keeps every bit.
  stuint(
    clamp(
      newTarget, cfg.rewardTargetFloor, stuint(cfg.rewardTargetCap, 512)),
    256)

func puzzleTicket*(claim: ClaimPowRewardPayload): FieldElement =
  ## The ticket of a claim: the hash of its key, block hash and epoch nonce.
  Poseidon2Hasher.digest([
    claim.publicKey, frFromBytesLEModOrder(claim.blockHash), claim.epochNonce])

func satisfies*(ticket: FieldElement, target: UInt256): bool =
  ## True when the integer value of `ticket` is below `target`.
  UInt256.fromBytesLE(encodeFieldElement(ticket)) < target

proc tryApplyClaim*(
    s: sink PowState, claim: ClaimPowRewardPayload, proof: ZkSigProof,
    txHash: Hash32, slot: SlotNumber,
    currentNonce, previousNonce: FieldElement,
    cfg: PowRewardConfig): Result[PowState, LedgerError] =
  ## Validates one claim and records its ticket and its payout.
  # The steps are those of the CLAIM_POW_REWARD validation, in order.
  # Step 1 reads the pool as the earlier claims of the block left it.
  if s.epochReward == 0 or s.rewardPool < s.epochReward:
    return err(PowRewardUnavailable)
  let anchorSlot = s.blockSlots.get(claim.blockHash).valueOr:
    return err(PowBlockOutsideWindow)
  # Step 2 requires 0 <= current_slot - block.slot <= WINDOW.
  if slot < anchorSlot or slot - anchorSlot > cfg.window:
    return err(PowBlockOutsideWindow)
  if claim.epochNonce != currentNonce and claim.epochNonce != previousNonce:
    return err(PowEpochNonceMismatch)
  let ticket = puzzleTicket(claim)
  if not ticket.satisfies(s.difficultyReward):
    return err(PowTicketAboveTarget)
  if ticket in s.nullifiers:
    return err(PowTicketClaimed)
  ?verifyZkSig(proof, txHash, [claim.publicKey])
  s.nullifiers = s.nullifiers.insert(ticket, anchorSlot)
  # Step 1 guarantees that this subtraction does not wrap.
  s.rewardPool -= s.epochReward
  s.claimsInBlock += 1
  ok(s)

func closeBlock*(
    s: sink PowState, blockId: Hash32, slot: SlotNumber,
    cfg: PowRewardConfig): PowState =
  ## Records the applied block, drops entries outside the window, retargets.
  s.blockSlots = s.blockSlots.insert(blockId, slot)
  # An entry outside the window fails step 2 also without the removal.
  # The removal only bounds the memory.
  var
    expiredBlocks: seq[Hash32]
    expiredTickets: seq[FieldElement]
  for (id, anchorSlot) in s.blockSlots.pairs:
    if slot - anchorSlot > cfg.window:
      expiredBlocks.add(id)
  for (ticket, anchorSlot) in s.nullifiers.pairs:
    if slot - anchorSlot > cfg.window:
      expiredTickets.add(ticket)
  for id in expiredBlocks:
    s.blockSlots = s.blockSlots.remove(id)
  for ticket in expiredTickets:
    s.nullifiers = s.nullifiers.remove(ticket)
  # A block is valid only if each of its claims is applied. So this count
  # is the number of claim operations in the block.
  s.difficultyReward = compute_new_reward_difficulty(
    s.claimsInBlock, s.difficultyReward, cfg)
  s.claimsInBlock = 0
  s

{.pop.}
