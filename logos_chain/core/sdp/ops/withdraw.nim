# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [1.1.0 Service Declaration Protocol](bedrock-service-declaration-protocol.md)

{.push raises: [], gcsafe.}

import
  results,
  std/sets,
  ./util,
  ../[registry, state],
  ../../crypto/types,
  ../../mantle/[operations, proofs],
  ../../../ledger/utxo_store

export util, registry, state

proc validateSdpWithdraw(
    withdraw: WithdrawMessage,
    proof: ZkSigProof,
    txHash: ZkHash,
    utxos: UtxoStore,
    state: SdpState,
    genesis: bool = false,
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

  if not genesis:
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
    genesis: bool = false,
): Result[void, LedgerError] =
  let declareInfo = ?validateSdpWithdraw(
    withdraw, proof, txHash, utxos, registry.state, genesis,
  )
  var declaration = registry.state.declarations.getOrDefault(withdraw.declarationId)
  declaration.nonce = withdraw.nonce
  declaration.withdrawAt = Opt.some(epoch)
  registry.state = insertDeclaration(
    registry.state, withdraw.declarationId, declaration,
  )
  ok()

{.pop.}
