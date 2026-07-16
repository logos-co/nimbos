# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## `LeaderClaim` validation + ledger application.

{.push raises: [], gcsafe.}

import
  results,
  ./[balance, types, leader_state, poc_verifier, cryptarchia_state],
  ../core/mantle/[operations, proofs, tx_hashing, utxo],
  ../utils/dynamic_merkle_tree as voucherTree

export leader_state, types

func applyLeaderClaimState*(
    s: sink CryptarchiaState,
    op: LeaderClaimPayload,
): Result[tuple[state: CryptarchiaState, balance: Balance], LedgerError] =
  ## Pure state transition: record nullifier, mint reward UTXO, debit pool.
  ## Caller must run PoC verify and cheap checks first.
  var leader = s.leader
  let recorded = ?leader.tryRecordClaim(op.voucherNullifier)
  leader = recorded.state
  let reward = recorded.reward

  let
    claimOpId = opId(op)
    note = Note(value: reward, zkPublicKey: op.publicKey)
    u = Utxo(opId: claimOpId, outputIndex: 0, note: note)
    newStore = s.utxos.insert(u.id, u).store

  ok((
    CryptarchiaState(utxos: newStore, leader: leader),
    Balance.zero,
  ))

proc tryApplyLeaderClaim*(
    s: sink CryptarchiaState,
    op: LeaderClaimPayload,
    proof: ProofOfClaimProof,
    txHash: ZkHash,
): Result[tuple[state: CryptarchiaState, balance: Balance], LedgerError] =
  ## Validates then applies a `LeaderClaim` op. Cheap checks run before PoC.
  if op.voucherNullifier in s.leader.spentNullifiers:
    return err(DuplicatedVoucherNullifier)
  let rewardsRoot = voucherTree.root(s.leader.voucherTree)
  if op.rewardsRoot != rewardsRoot:
    return err(RewardsRootMismatch)

  let public = proofOfClaimPublic(op, rewardsRoot, txHash)
  let verified = verifyProofOfClaim(proof, public).valueOr:
    return err(VerifierNotInitialised)
  if not verified:
    return err(InvalidProof)

  s.applyLeaderClaimState(op)

{.pop.}
