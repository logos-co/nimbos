# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [1.1.0 Service Declaration Protocol](https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/bedrock-service-declaration-protocol.md)

{.push raises: [], gcsafe.}

import
  results,
  std/sets,
  ./util,
  ../[registry, state],
  ../../utxo_store,
  ../../../core/crypto/types,
  ../../../core/mantle/[operations, proofs]

export util, registry, state

proc validateSdpWithdraw(
    withdraw: WithdrawMessage,
    proof: ZkSigProof,
    txHash: ZkHash,
    utxos: UtxoStore,
    state: SdpState,
): Result[DeclarationInfo, LedgerError] =
  let declareInfo = ?loadDeclaration(state, withdraw.declarationId)
  ?checkNotWithdrawn(declareInfo)
  ?checkNonceMonotonic(declareInfo, withdraw.nonce)

  if withdraw.lockedNoteId != declareInfo.lockedNoteId:
    return err(LockedNoteIdMismatch)

  let lockedNote = getLockedNote(state, withdraw.lockedNoteId).valueOr:
    return err(LockedNoteNotFound)
  if withdraw.declarationId notin lockedNote:
    return err(DeclarationNotInLockedNote)

  let utxo = utxos.get(withdraw.lockedNoteId).valueOr:
    return err(LockedNoteNotFound)
  ?verifyZkSig(proof, txHash, @[utxo.note.zkPublicKey, declareInfo.zkId])

  ok(declareInfo)

proc tryApplySdpWithdraw*(
    registry: var SdpRegistry,
    withdraw: WithdrawMessage,
    proof: ZkSigProof,
    txHash: ZkHash,
    utxos: UtxoStore,
    epoch: EpochNumber,
): Result[void, LedgerError] =
  var declaration = ?validateSdpWithdraw(
    withdraw, proof, txHash, utxos, registry.state,
  )
  declaration.nonce = withdraw.nonce
  declaration.withdrawAt = Opt.some(epoch)
  registry.state = insertDeclaration(
    registry.state, withdraw.declarationId, declaration,
  )
  ok()

{.pop.}
