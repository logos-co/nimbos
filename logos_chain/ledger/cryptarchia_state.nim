# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## `CryptarchiaState` — UTXO bookkeeping + `tryApplyTransfer`.

{.push raises: [], gcsafe.}

import results

import
  ./[balance, types, locked_notes, utxo_store],
  ../core/mantle/[primitives, operations, proofs, utxo, tx_hashing],
  ../zk/zksign

export types, utxo, primitives, utxo_store

type CryptarchiaState* = object
  utxos*: UtxoStore

func init*(_: typedesc[CryptarchiaState]): CryptarchiaState =
  CryptarchiaState(utxos: UtxoStore.init())

func init*(_: typedesc[CryptarchiaState], utxos: UtxoStore): CryptarchiaState =
  CryptarchiaState(utxos: utxos)

func init*(_: typedesc[CryptarchiaState], seed: openArray[Utxo]): CryptarchiaState =
  ## Builds a fresh store seeded with the given UTXOs (genesis-style).
  var s = UtxoStore.init()
  for u in seed:
    s = s.insert(u.id, u).store
  CryptarchiaState(utxos: s)

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
  a.utxos == b.utxos

func applyTransferState*(
    s: sink CryptarchiaState,
    lockedNotes: LockedNotes,
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
    if lockedNotes.contains(inputId):
      return err(LockedNote)
    let (newStore, removedUtxo) = s.utxos.remove(inputId).valueOr:
      return err(InvalidNote)
    s = CryptarchiaState(utxos: newStore)
    balance = ?balance.checkedAdd(i128(removedUtxo.note.value))
    pks.add(removedUtxo.note.zkPublicKey)

  let transferOpId = opId(op)
  for i, outNote in op.outputs.notes:
    if outNote.value == 0:
      return err(ZeroValueNote)
    balance = ?balance.checkedSub(i128(outNote.value))
    let u = Utxo(opId: transferOpId, outputIndex: uint64(i), note: outNote)
    s = CryptarchiaState(utxos: s.utxos.insert(u.id, u).store)

  ok((s, balance, pks))

proc tryApplyTransfer*(
    s: sink CryptarchiaState,
    lockedNotes: LockedNotes,
    op: TransferPayload,
    sig: ZkSigProof,
    txHash: ZkHash,
): Result[tuple[state: CryptarchiaState, balance: Balance], LedgerError] =
  ## Applies a `TransferPayload` to the cryptarchia state and verifies the
  ## ZkSig over the collected input pks. Returns
  ## `(new_state, sum(inputs) − sum(outputs))`. The returned balance may be
  ## positive (surplus → fees), zero (balanced), or negative (deficit).
  let r = ?s.applyTransferState(lockedNotes, op)

  # `txHash` is a Blake2b-256 digest that may exceed the BN254 field order;
  # reduce mod p so the prover and verifier agree on the signed Fr.
  let msgFr = frFromBytesLEModOrder(txHash)
  let input = zksignInput(r.pks, msgFr).valueOr:
    return err(InvalidProof)
  let verified = zksign.verify(sig, input).valueOr:
    return err(VerifierNotInitialised)
  if not verified:
    return err(InvalidProof)

  ok((r.state, r.balance))

{.pop.}
