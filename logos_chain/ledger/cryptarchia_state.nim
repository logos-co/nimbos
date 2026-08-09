# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## `CryptarchiaState` — UTXO bookkeeping, `tryApplyTransfer`, and `tryApplyLeaderClaim`.

{.push raises: [], gcsafe.}

import results

import
  ./[
    balance, channel_notes, types, utxo_store, zksig_verify, leader_state,
    poc_verifier,
  ],
  ./sdp/state as sdp_state,
  ../core/mantle/[primitives, operations, proofs, utxo, tx_hashing],
  ../utils/dynamic_merkle_tree as voucherTree

export types, utxo, primitives, utxo_store, sdp_state, leader_state, channel_notes

type
  CryptarchiaState* = object
    utxos*: UtxoStore
    leader*: LeaderState

func init*(_: typedesc[CryptarchiaState]): CryptarchiaState =
  CryptarchiaState(utxos: UtxoStore.init(), leader: LeaderState.init())

func init*(_: typedesc[CryptarchiaState], utxos: UtxoStore): CryptarchiaState =
  CryptarchiaState(utxos: utxos, leader: LeaderState.init())

func init*(_: typedesc[CryptarchiaState], seed: openArray[Utxo]): CryptarchiaState =
  ## Builds a fresh store seeded with the given UTXOs (genesis-style).
  var s = UtxoStore.init()
  for u in seed:
    s = s.insert(u.id, u).store
  CryptarchiaState(utxos: s, leader: LeaderState.init())

func len*(s: CryptarchiaState): int =
  s.utxos.len

func isEmpty*(s: CryptarchiaState): bool =
  s.utxos.isEmpty

func root*(s: CryptarchiaState): FieldElement =
  s.utxos.root

func latestUtxos*(s: CryptarchiaState): lent UtxoStore =
  ## The live UTXO set. Distinct from `agedUtxos` (frozen epoch snapshot
  ## for leader-proof public inputs).
  s.utxos

func `==`*(a, b: CryptarchiaState): bool =
  a.utxos == b.utxos and a.leader == b.leader

func applyTransferState*(
    s: sink CryptarchiaState,
    lockedNotes: LockedNotes,
    channelNotes: ChannelNotes,
    op: TransferPayload,
): Result[
  tuple[state: CryptarchiaState, balance: Balance, pks: seq[ZkPublicKey]],
  LedgerError,
] =
  ## Pure state transition for a `TransferPayload`, removes inputs, inserts
  ## outputs, sums balance. No signature verify; the caller must run
  ## `zksign.verify` over the returned `pks` ++ tx hash.
  var
    balance = Balance.zero
    pks = newSeqOfCap[ZkPublicKey](op.inputs.noteIds.len)

  for inputId in op.inputs.noteIds:
    if inputId in lockedNotes:
      return err(LockedNote)
    # A channel note is owned by its channel and only CHANNEL_TRANSFER or
    # CHANNEL_WITHDRAW may move it.
    if channelNotes.isChannelNote(inputId):
      return err(ChannelNoteSpend)
    let (newStore, removedUtxo) = s.utxos.remove(inputId).valueOr:
      return err(InvalidNote)
    s.utxos = newStore
    balance = ?balance.checkedAdd(i128(removedUtxo.note.value))
    pks.add(removedUtxo.note.zkPublicKey)

  let transferOpId = opId(op)
  for i, outNote in op.outputs.notes:
    if outNote.value == 0:
      return err(ZeroValueNote)
    balance = ?balance.checkedSub(i128(outNote.value))
    let u = Utxo(opId: transferOpId, outputIndex: uint64(i), note: outNote)
    s.utxos = s.utxos.insert(u.id, u).store

  ok((s, balance, pks))

proc tryApplyTransfer*(
    s: sink CryptarchiaState,
    lockedNotes: LockedNotes,
    channelNotes: ChannelNotes,
    op: TransferPayload,
    sig: ZkSigProof,
    txHash: ZkHash,
): Result[tuple[state: CryptarchiaState, balance: Balance], LedgerError] =
  ## Applies a `TransferPayload` to the cryptarchia state and verifies the
  ## ZkSig over the collected input pks. Returns
  ## `(new_state, sum(inputs) − sum(outputs))`. The returned balance may be
  ## positive (surplus → fees), zero (balanced), or negative (deficit).
  let r = ?s.applyTransferState(lockedNotes, channelNotes, op)
  ?verifyZkSig(sig, txHash, r.pks)
  ok((r.state, r.balance))

proc tryApplyLeaderClaim*(
    s: sink CryptarchiaState,
    op: LeaderClaimPayload,
    proof: ProofOfClaimProof,
    txHash: ZkHash,
    verifyProof: ProofOfClaimVerifier = verifyProofOfClaim,
): Result[CryptarchiaState, LedgerError] =
  let (leader, reward) = ?s.leader.tryRecordClaim(op, proof, txHash, verifyProof)
  let
    u = Utxo(
      opId: opId(op), outputIndex: 0,
      note: Note(value: reward, zkPublicKey: op.publicKey),
    )
    newStore = s.utxos.insert(u.id, u).store
  ok(CryptarchiaState(utxos: newStore, leader: leader))

{.pop.}
