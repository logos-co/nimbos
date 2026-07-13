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
  ../core/crypto/types,
  ../time/clock

export results, clock

type
  LedgerError* {.pure.} = enum
    ## Consensus rejection categories. New variants land with the modules
    ## that emit them.
    ParentNotFound ## prepareUpdate's parent_id is not in the map
    InvalidNote ## input NoteId not in UtxoStore
    LockedNote ## input NoteId is locked by SDP
    DoubleSpend ## same NoteId appears twice within a single op's inputs
    ZeroValueNote ## output Note has value == 0
    InvalidProof ## ZK multi-sig or leader-proof verify failed
    BalanceOverflow ## add/sub overflowed during balance math
    UnsupportedOp ## Op kind not yet wired in this ledger version
    UnbalancedTransaction ## inputs - outputs > fees
    InsufficientBalance ## not enough balance for the requested debit
    VerifierNotInitialised ## per-circuit VK singleton wasn't installed at
      ## node startup — wiring bug, not adversarial input
    # SDP (Service Declaration Protocol)
    EmptyLocators ## SDP Declare locators must contain at least one element
    TooManyLocators
    InvalidLocator
    DuplicateDeclaration
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
    ActivityRejected
    ChannelNotFound ## ChannelDeposit/Withdraw references a missing ChannelId
    InvalidParent ## ChannelInscribe parent doesn't match the channel's tipMessage
    UnauthorizedSigner ## ChannelInscribe signer isn't the round-robin sequencer
    InvalidWithdrawNonce ## ChannelWithdraw opIdNonce != channel's withdrawalNonce
    ThresholdUnmet ## Config/Withdraw signature count != channel threshold
    InvalidChannelConfig ## ChannelConfig has zero threshold or empty keys
    WithdrawNonceOverflow ## ChannelWithdraw incremented withdrawalNonce past uint32
    UnsupportedLotteryF ## no lottery constants registered for the configured `f`
    InvalidSlot ## header slot is not strictly greater than the parent state's
    InputInGenesis ## genesis transfer consumes inputs; genesis may only mint

  LedgerConfig* = object
    ## Chain configuration. Remaining fields land with the modules that
    ## need them (SDP, gas).
    epochSchedule*: EpochSchedule
    slotActivationCoeff*: NonNegativeRatio ## f
    stakeInferenceLearningRate*: NonNegativeRatio ## beta
    faucetPk*: Opt[ZkPublicKey] ## excluded from the genesis total-stake sum

{.pop.}
