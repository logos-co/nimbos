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
  std/sets,
  ./[channel_state, cryptarchia_state, types],
  ../core/mantle/[primitives, operations, proofs]

export channel_state

type
  MantleState* = object
    channels*: ChannelStore

func init*(_: typedesc[MantleState]): MantleState =
  MantleState(channels: HashTrieMap[ChannelId, ChannelState].init())

func tryApplyChannelInscribe*(
    ms: sink MantleState,
    op: ChannelInscribePayload,
    sig: Ed25519Signature,
    txHash: Hash32,
    blockSlot: SlotNumber,
): Result[MantleState, LedgerError] =
  ## ChannelInscribe — validate-then-apply.
  ?validateChannelInscribe(ms.channels, op, sig, txHash, blockSlot)
  ms.channels = applyChannelInscribe(ms.channels, op, blockSlot)
  ok(ms)

func tryApplyChannelConfig*(
    ms: sink MantleState,
    op: ChannelConfigPayload,
    proof: ChannelWithdrawOpProof,
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
  ## ChannelDeposit — consumes input UTXOs from cryptarchia and credits the
  ## channel balance. Validate-then-apply.
  ?validateChannelDeposit(ms.channels, cs, lockedNotes, op, sig, txHash)
  let (newChans, newCs) = ?applyChannelDeposit(ms.channels, cs, op)
  ms.channels = newChans
  ok((ms, newCs))

func tryApplyChannelWithdraw*(
    ms: sink MantleState,
    cs: sink CryptarchiaState,
    op: ChannelWithdrawPayload,
    proof: ChannelWithdrawOpProof,
    txHash: Hash32,
): Result[tuple[ms: MantleState, cs: CryptarchiaState], LedgerError] =
  ## ChannelWithdraw — drains the channel balance and inserts output UTXOs
  ## into cryptarchia. Validate-then-apply.
  ?validateChannelWithdraw(ms.channels, op, proof, txHash)
  let (newChans, newCs) = applyChannelWithdraw(ms.channels, cs, op)
  ms.channels = newChans
  ok((ms, newCs))

{.pop.}
