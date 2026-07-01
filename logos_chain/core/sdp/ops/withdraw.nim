# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP Withdraw validation and application.
## Spec: [1.0.0 Service Declaration Protocol](https://nomos-tech.notion.site/1-0-0-Service-Declaration-Protocol-1fd261aa09df819ca9f8eb2bdfd4ec1d)

{.push raises: [], gcsafe.}

import
  results,
  std/[sets, tables],
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
    blockHeight: BlockNumber,
): Result[void, LedgerError] =
  ## Validates a ``WithdrawMessage`` per SDP Withdraw rules.
  let utxo = utxos.get(withdraw.lockedNoteId).valueOr:
    return err(LockedNoteNotFound)
  let note = utxo.note

  let lockedNote = getLockedNote(state, withdraw.lockedNoteId).valueOr:
    return err(LockedNoteNotFound)
  if withdraw.declarationId notin lockedNote.declarations:
    return err(DeclarationNotInLockedNote)

  if lockedNote.lockedUntil > blockHeight:
    return err(LockPeriodActive)

  let declareInfo = ?loadDeclaration(state, withdraw.declarationId)
  if withdraw.lockedNoteId != declareInfo.lockedNoteId:
    return err(LockedNoteIdMismatch)

  ?verifyZkSig(proof, txHash, @[note.zkPublicKey, declareInfo.zkId])
  ?checkNotWithdrawn(declareInfo)
  ?checkNonceMonotonic(declareInfo, withdraw.nonce)

  ok()

proc tryApplySdpWithdraw*(
    registry: var SdpRegistry,
    withdraw: WithdrawMessage,
    proof: ZkSigProof,
    txHash: ZkHash,
    utxos: UtxoStore,
    blockHeight: BlockNumber,
): Result[void, LedgerError] =
  ?validateSdpWithdraw(
    withdraw, proof, txHash, utxos, registry.state, blockHeight,
  )
  var declaration = registry.state.declarations.getOrDefault(withdraw.declarationId)
  declaration.nonce = withdraw.nonce
  declaration.withdrawn = blockHeight
  registry.state.declarations[withdraw.declarationId] = declaration
  removeDeclarationFromLockedNote(
    registry.state, withdraw.lockedNoteId, withdraw.declarationId,
  )
  indexEvent(
    registry,
    EventType.withdrawn,
    declaration.service,
    blockHeight,
    withdraw.declarationId,
  )
  ok()

{.pop.}
