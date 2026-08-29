# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## `MantleState` bundles all Mantle-side sub-states under one composite:
## channels and their notes now, SDP and leader sub-states in later PRs.

{.push raises: [], gcsafe.}

import
  results,
  ./[channel_state, cryptarchia_state, types],
  ../core/mantle/[primitives, operations, proofs]

export channel_state

type
  MantleState* = object
    channels*: ChannelStore
    channelNotes*: ChannelNotes

func init*(_: typedesc[MantleState]): MantleState =
  MantleState(
    channels: HashTrieMap[ChannelId, ChannelState].init(),
    channelNotes: ChannelNotes.init(),
  )

func tryApplyChannelInscribe*(
    ms: sink MantleState,
    op: ChannelInscribePayload,
    blockSlot: SlotNumber,
): Result[MantleState, LedgerError] =
  ## ChannelInscribe — validate-then-apply.
  ?validateChannelInscribe(ms.channels, op, blockSlot)
  ms.channels = applyChannelInscribe(ms.channels, op, blockSlot)
  ok(ms)

func tryApplyChannelConfig*(
    ms: sink MantleState,
    op: ChannelConfigPayload,
    proof: ChannelMultiSigProof,
    txHash: Hash32,
    blockSlot: SlotNumber,
): Result[MantleState, LedgerError] =
  ## ChannelConfig — validate-then-apply.
  ?validateChannelConfig(ms.channels, op, proof, txHash)
  ms.channels = applyChannelConfig(ms.channels, op, blockSlot)
  ok(ms)

proc tryApplyChannelDeposit*(
    ms: sink MantleState,
    cs: sink CryptarchiaState,
    lockedNotes: LockedNotes,
    op: ChannelDepositPayload,
    sig: ZkSigProof,
    txHash: Hash32,
): Result[tuple[ms: MantleState, cs: CryptarchiaState], LedgerError] =
  ## ChannelDeposit — consumes the input UTXOs and re-creates them as channel
  ## notes. Validate-then-apply.
  ?validateChannelDeposit(
    ms.channels, ms.channelNotes, cs, lockedNotes, op, sig, txHash)
  let r = ?applyChannelDeposit(ms.channelNotes, cs, op)
  ms.channelNotes = r.channelNotes
  ok((ms, r.cs))

func tryApplyChannelWithdraw*(
    ms: sink MantleState,
    cs: CryptarchiaState,
    lockedNotes: LockedNotes,
    op: ChannelWithdrawPayload,
    proof: ChannelMultiSigProof,
    txHash: Hash32,
): Result[MantleState, LedgerError] =
  ## ChannelWithdraw — releases the inputs from the channel; the UTXO set is
  ## untouched. Validate-then-apply.
  ?validateChannelWithdraw(
    ms.channels, ms.channelNotes, cs, lockedNotes, op, proof, txHash)
  ms.channelNotes = ?applyChannelWithdraw(ms.channelNotes, op)
  ok(ms)

func tryApplyChannelTransfer*(
    ms: sink MantleState,
    cs: sink CryptarchiaState,
    lockedNotes: LockedNotes,
    op: ChannelTransferPayload,
    proof: ChannelMultiSigProof,
    txHash: Hash32,
): Result[tuple[ms: MantleState, cs: CryptarchiaState], LedgerError] =
  ## ChannelTransfer — reassigns channel funds to new keys. Validate-then-apply.
  ?validateChannelTransfer(
    ms.channels, ms.channelNotes, cs, lockedNotes, op, proof, txHash)
  let r = ?applyChannelTransfer(ms.channelNotes, cs, op)
  ms.channelNotes = r.channelNotes
  ok((ms, r.cs))

{.pop.}
