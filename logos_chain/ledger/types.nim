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
  ../core/types,
  ../core/crypto/types,
  ../consensus/clock,
  ./pol_verifier

export results, clock, pol_verifier

type
  LedgerError* {.pure.} = enum
    ParentNotFound ## prepareUpdate's parent_id is not in the map
    InvalidNote ## input NoteId not in UtxoStore
    LockedNote ## input NoteId is locked by SDP
    InvalidProofOfLeadership ## Proof of Leadership (Cryptarchia) verify failed
    InvalidTxProof ## ZK multi-sig, transfer, or channel proof verify failed
    BalanceOutOfRange ## balance math left the representable range
    UnsupportedOp ## Op kind not yet wired in this ledger version
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
    MalformedActivityMetadata ## Active metadata failed to decode
    TargetEpochNotSet ## SDP Active submitted while no target epoch is set
    InvalidEpoch ## activity proof's epoch is not the target epoch
    UnknownProvider ## activity submitter is not in the target-epoch snapshot
    HammingDistanceTooLarge ## activity token lost the Hamming lottery
    DuplicateActiveMessage ## provider already submitted for the target epoch
    ChannelNotFound ## channel op references a missing ChannelId
    InvalidParent ## ChannelInscribe parent doesn't match the channel's tipMessage
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
    InputInGenesis ## genesis transfer consumes inputs; genesis may only mint

  LeaderProofVerifier* = proc(
    proof: ProofOfLeadership, public: LeaderPublic
  ): Result[bool, PolLoadError] {.gcsafe, raises: [].}
  LedgerConfig* = object
    ## Chain configuration. Remaining fields land with the modules that
    ## need them (SDP).
    epochSchedule*: EpochSchedule
    slotActivationCoeff*: NonNegativeRatio ## f — exact, keyed into the lottery table
    learningRateFixed*: uint64 ## fixedPoint(beta) — stake-inference input
    faucetPk*: Opt[ZkPublicKey] ## excluded from the genesis total-stake sum

{.pop.}
