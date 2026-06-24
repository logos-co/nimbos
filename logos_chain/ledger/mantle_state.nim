# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## `MantleState` bundles all Mantle-side sub-states under one composite:
## `channels` now, SDP and leader sub-states in later PRs.
##
## The validate-then-apply composition for Inscribe/Config/Withdraw lives
## here; the channel_state primitives are the building blocks. Deposit uses
## the apply-then-verify pattern (zkSig verify consumes pks collected
## during UTXO removal — same as cryptarchia's Transfer).

{.push raises: [], gcsafe.}

import
  std/tables,
  results,
  ./[balance, channel_state, cryptarchia_state, locked_notes, types],
  ../core/mantle/[primitives, operations, proofs]

export channel_state

type
  MantleState* = object
    channels*: ChannelStore

func init*(_: typedesc[MantleState]): MantleState =
  MantleState(channels: initTable[ChannelId, ChannelState]())

func tryApplyChannelInscribe*(
    ms: sink MantleState,
    op: ChannelInscribePayload,
    sig: Ed25519Signature,
    txHash: Hash32,
    blockSlot: SlotNumber,
): Result[MantleState, LedgerError] =
  ## ChannelInscribe — validate-then-apply.
  ?validateChannelInscribe(ms.channels, op, sig, txHash, blockSlot)
  ok(MantleState(channels: applyChannelInscribe(ms.channels, op, blockSlot)))

func tryApplyChannelConfig*(
    ms: sink MantleState,
    op: ChannelConfigPayload,
    proof: ChannelWithdrawOpProof,
    txHash: Hash32,
    blockSlot: SlotNumber,
): Result[MantleState, LedgerError] =
  ## ChannelConfig — validate-then-apply.
  ?validateChannelConfig(ms.channels, op, proof, txHash)
  ok(MantleState(channels: applyChannelConfig(ms.channels, op, blockSlot)))

proc tryApplyChannelDeposit*(
    ms: sink MantleState,
    cs: sink CryptarchiaState,
    lockedNotes: LockedNotes,
    op: ChannelDepositPayload,
    sig: ZkSigProof,
    txHash: Hash32,
): Result[
    tuple[ms: MantleState, cs: CryptarchiaState, balance: Balance],
    LedgerError,
] =
  ## ChannelDeposit crosses ledgers — input UTXOs consumed, channel balance
  ## credited. Apply-then-verify pattern (matches cryptarchia's Transfer):
  ## the zkSig verify uses `pks` collected during UTXO removal.
  let r = ?tryApplyChannelDeposit(
    ms.channels, cs, lockedNotes, op, sig, txHash)
  ok((MantleState(channels: r.channels), r.cs, r.balance))

func tryApplyChannelWithdraw*(
    ms: sink MantleState,
    cs: sink CryptarchiaState,
    op: ChannelWithdrawPayload,
    proof: ChannelWithdrawOpProof,
    txHash: Hash32,
): Result[
    tuple[ms: MantleState, cs: CryptarchiaState, balance: Balance],
    LedgerError,
] =
  ## ChannelWithdraw crosses ledgers — channel balance drained, output
  ## UTXOs inserted. Validate-then-apply; validate returns outflow.
  let
    outflow = ?validateChannelWithdraw(ms.channels, op, proof, txHash)
    (newChans, newCs) = applyChannelWithdraw(ms.channels, cs, op, outflow)
  ok((MantleState(channels: newChans), newCs, outflow))

{.pop.}
