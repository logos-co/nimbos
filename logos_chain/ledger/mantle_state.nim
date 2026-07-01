# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## `MantleState` bundles all Mantle-side sub-states under one composite:
## `channels` now, SDP and leader sub-states in later PRs.

{.push raises: [], gcsafe.}

import
  results,
  ./[channel_state, cryptarchia_state, locked_notes, types],
  ../core/mantle/[primitives, operations, proofs]

export channel_state

type
  MantleState* = object
    channels*: ChannelStore

func init*(_: typedesc[MantleState]): MantleState =
  MantleState(channels: HashTrieMap[ChannelId, ChannelState].init())

func tryApplyChannelInscribe*(
    ms: MantleState,
    op: ChannelInscribePayload,
    sig: Ed25519Signature,
    txHash: Hash32,
    blockSlot: SlotNumber,
): Result[MantleState, LedgerError] =
  ## ChannelInscribe — validate-then-apply.
  ?validateChannelInscribe(ms.channels, op, sig, txHash, blockSlot)
  ok(MantleState(channels: applyChannelInscribe(ms.channels, op, blockSlot)))

func tryApplyChannelConfig*(
    ms: MantleState,
    op: ChannelConfigPayload,
    proof: ChannelWithdrawOpProof,
    txHash: Hash32,
    blockSlot: SlotNumber,
): Result[MantleState, LedgerError] =
  ## ChannelConfig — validate-then-apply.
  ?validateChannelConfig(ms.channels, op, proof, txHash)
  ok(MantleState(channels: applyChannelConfig(ms.channels, op, blockSlot)))

proc tryApplyChannelDeposit*(
    ms: MantleState,
    cs: CryptarchiaState,
    lockedNotes: LockedNotes,
    op: ChannelDepositPayload,
    sig: ZkSigProof,
    txHash: Hash32,
): Result[tuple[ms: MantleState, cs: CryptarchiaState], LedgerError] =
  ## ChannelDeposit — consumes input UTXOs from cryptarchia and credits the
  ## channel balance. Validate-then-apply.
  ?validateChannelDeposit(ms.channels, cs, lockedNotes, op, sig, txHash)
  let (newChans, newCs) = ?applyChannelDeposit(ms.channels, cs, op)
  ok((MantleState(channels: newChans), newCs))

func tryApplyChannelWithdraw*(
    ms: MantleState,
    cs: CryptarchiaState,
    op: ChannelWithdrawPayload,
    proof: ChannelWithdrawOpProof,
    txHash: Hash32,
): Result[tuple[ms: MantleState, cs: CryptarchiaState], LedgerError] =
  ## ChannelWithdraw — drains the channel balance and inserts output UTXOs
  ## into cryptarchia. Validate-then-apply.
  ?validateChannelWithdraw(ms.channels, op, proof, txHash)
  let (newChans, newCs) = applyChannelWithdraw(ms.channels, cs, op)
  ok((MantleState(channels: newChans), newCs))

{.pop.}
