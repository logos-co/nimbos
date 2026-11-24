# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Ledger module common types.
##
## `LedgerError` is a flat `{.pure.}` enum: coarse rejection categories, no
## carried payload — per-rejection detail goes to logs at the rejection site.

{.push raises: [], gcsafe.}

import
  results,
  stint,
  ../core/types,
  ../consensus/clock,
  ./pol_verifier

export results, clock, pol_verifier

type
  LedgerError* {.pure.} = enum
    ParentNotFound ## prepareUpdate's parent_id is not in the map
    InvalidNote ## input NoteId not in UtxoStore
    LockedNote ## input NoteId is locked by SDP
    InvalidProofOfLeadership ## Proof of Leadership (Cryptarchia) verify failed
    PermanentInvalidTxProof ## Cryptographic proof permanently invalid (e.g. ZkSig Groth16, proof kind mismatch)
    InvalidTxProof ## Transaction proof verification failed against current state (e.g. channel multisig, SDP activity)
    BalanceOutOfRange ## balance math left the representable range
    UnsupportedOp ## opcode the encoder does not know
    InsufficientBalance ## not enough balance for the requested debit
    GasOverflow ## gas or fee arithmetic exceeded uint64
    TooMuchExecutionGas ## block's summed execution gas exceeds the per-block limit
    VerifierNotInitialised ## per-circuit VK singleton wasn't installed at
      ## node startup — wiring bug, not adversarial input
    # SDP (Service Declaration Protocol)
    DuplicateDeclaration
    DuplicateProviderOrZkId
    LockedNoteNotFound
    InsufficientStake
    LockedNoteServiceConflict
    MissingServiceParameters
    MinStakeNotFound
    DeclarationNotFound
    AlreadyWithdrawn
    InvalidNonce
    LockedNoteIdMismatch
    DeclarationNotInLockedNote
    TargetEpochNotSet ## SDP Active submitted while no target epoch is set
    InvalidEpoch ## op epoch out of range
    UnknownProvider ## activity submitter is not in the target-epoch snapshot
    HammingDistanceTooLarge ## activity token lost the Hamming lottery
    DuplicateActiveMessage ## provider already submitted for the target epoch
    ChannelNotFound ## channel op references a missing ChannelId
    InvalidParent ## Inscribe or Config parent doesn't match `tipHash` / `configTipHash`
    UnauthorizedSigner ## ChannelInscribe signer isn't the round-robin sequencer
    ThresholdUnmet ## Config/Withdraw/Transfer signature count != channel threshold
    ChannelNoteSpend ## channel note used where a channel-free note is required
    AlreadyChannelNote ## NoteId is already registered to a channel
    NotAChannelNote ## Withdraw/Transfer input isn't owned by the named channel
    UnbalancedTransfer ## ChannelTransfer input sum != output sum
    DuplicatedVoucherNullifier ## leader-claim voucher nullifier already spent
    RewardsRootMismatch ## leader-claim rewards root ≠ ledger snapshot
    UnsupportedLotteryF ## no lottery constants registered for the configured `f`
    InvalidSlot ## header slot is not strictly greater than the parent state's
    TotalStakeOverflow ## genesis stake sum exceeds uint64
    # Proof of work (CLAIM_POW_REWARD), one variant for each validation step
    PowRewardUnavailable ## the reward per claim is zero or above the pool
    PowBlockOutsideWindow ## the claimed block is unknown or outside the window
    PowEpochNonceMismatch ## the nonce is not the current or the previous epoch nonce
    PowTicketAboveTarget ## the ticket is not below the reward threshold
    PowTicketClaimed ## the ticket was claimed before

  LeaderProofVerifier* = proc(
    proof: ProofOfLeadership, public: LeaderPublic
  ): Result[bool, PolLoadError] {.gcsafe, raises: [].}
  PowRewardConfig* = object
    ## Proof-of-work reward parameters, derived from the deployment settings.
    genesisPool*: TokenValue
    rateNum*: uint64
    rateDenominator*: UInt256 ## rate_den * target_claims_per_block * N_b
    powShare*: uint64
    shareDen*: uint64
    rewardTargetCap*: UInt256
    # The retarget runs in 512 bits. These values have that width, so each
    # block does not convert them again.
    rewardTargetFloor*: StUint[512]
    emaSmoothingFactor*: StUint[512]
    emaSmoothingPrecision*: StUint[512]
    targetClaimsPerBlock*: StUint[512]
    window*: uint64 ## acceptance window, in slots

  LedgerConfig* = object
    ## Chain configuration. Remaining fields land with the modules that
    ## need them (SDP).
    epochSchedule*: EpochSchedule
    slotActivationCoeff*: NonNegativeRatio ## f — exact, keyed into the lottery table
    learningRateFixed*: uint64 ## fixedPoint(beta) — stake-inference input
    faucetPk*: Opt[ZkPublicKey] ## excluded from the genesis total-stake sum
    uncleWindowSlots*: uint64 ## ⌊W / f⌋, the uncle reference window in slots
    pow*: PowRewardConfig

func toLedgerError*(err: EncodingError): LedgerError =
  case err
  of EncodingError.UnsupportedOpcode:
    LedgerError.UnsupportedOp
  else:
    LedgerError.PermanentInvalidTxProof

{.pop.}
