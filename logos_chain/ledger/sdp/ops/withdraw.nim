# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [Service Declaration Protocol v1.3.0](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-service-declaration-protocol.md)

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

proc applySdpWithdraw*(
    registry: sink SdpRegistry,
    withdraw: WithdrawMessage,
    declaration: DeclarationInfo,
    epoch: EpochNumber,
): SdpRegistry =
  ## Mutation only; assumes validation passed.
  var updated = declaration
  updated.nonce = withdraw.nonce
  updated.withdrawAt = Opt.some(epoch)
  registry.state = insertDeclaration(
    registry.state, withdraw.declarationId, updated,
  )
  registry

proc tryApplySdpWithdraw*(
    registry: sink SdpRegistry,
    withdraw: WithdrawMessage,
    proof: ZkSigProof,
    txHash: ZkHash,
    utxos: UtxoStore,
    epoch: EpochNumber,
): Result[SdpRegistry, LedgerError] =
  let declaration = ?validateSdpWithdraw(
    withdraw, proof, txHash, utxos, registry.state,
  )
  ok(applySdpWithdraw(registry, withdraw, declaration, epoch))

{.pop.}
