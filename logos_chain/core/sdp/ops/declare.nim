# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP Declare validation and application.
## Spec: [1.0.0 Service Declaration Protocol](https://nomos-tech.notion.site/1-0-0-Service-Declaration-Protocol-1fd261aa09df819ca9f8eb2bdfd4ec1d)

{.push raises: [], gcsafe.}

import
  results,
  std/sequtils,
  libp2p/crypto/ed25519/ed25519,
  ./util,
  ../[registry, state],
  ../../crypto/types,
  ../../mantle/[operations, proofs],
  ../../../ledger/utxo_store

export util, registry, state

proc verifySdpDeclareProofs*(
    declaration: DeclarationMessage,
    proof: ZkAndEd25519SigsProof,
    txHash: ZkHash,
    noteZkPublicKey: ZkPublicKey,
): Result[void, LedgerError] =
  if not verify(
    proof.ed25519Sig, txHash, declaration.providerId,
  ):
    return err(InvalidProof)
  ?verifyZkSig(proof.zkSig, txHash, @[noteZkPublicKey, declaration.zkId])

proc validateSdpDeclare(
    declaration: DeclarationMessage,
    proof: ZkAndEd25519SigsProof,
    txHash: ZkHash,
    minStake: MinStake,
    utxos: UtxoStore,
    state: SdpState,
    genesis: bool = false,
): Result[DeclarationId, LedgerError] =
  let utxo = utxos.get(declaration.lockedNoteId).valueOr:
    return err(LockedNoteNotFound)
  let note = utxo.note

  if not genesis:
    ?verifySdpDeclareProofs(
      declaration, proof, txHash, note.zkPublicKey,
    )

  let declarationId = declarationId(declaration)
  if declarationId in state.declarations:
    return err(DuplicateDeclaration)

  if declaration.locators.len > MaxSdpLocators:
    return err(TooManyLocators)
  if not declaration.locators.allIt(isValidLocator(it)):
    return err(InvalidLocator)

  if note.value < minStake.stakeThreshold:
    return err(InsufficientStake)

  if lockedNoteHasService(state, declaration.lockedNoteId, declaration.serviceType):
    return err(LockedNoteServiceConflict)

  ok(declarationId)

proc tryApplySdpDeclare*(
    registry: var SdpRegistry,
    declaration: DeclarationMessage,
    proof: ZkAndEd25519SigsProof,
    txHash: ZkHash,
    utxos: UtxoStore,
    blockHeight: BlockNumber,
    genesis: bool = false,
): Result[void, LedgerError] =
  let minStake = getMinStakeAt(registry, blockHeight).valueOr:
    return err(MinStakeNotFound)
  let declarationId = ?validateSdpDeclare(
    declaration, proof, txHash, minStake, utxos, registry.state, genesis,
  )
  let params = getParametersAt(
    registry, declaration.serviceType, blockHeight,
  ).valueOr:
    return err(MissingServiceParameters)
  registry.state = insertDeclaration(
    addDeclarationToLockedNote(
      registry.state,
      declaration.lockedNoteId,
      declarationId,
      blockHeight + params.lockPeriod,
    ),
    declarationId,
    DeclarationInfo(
      service: declaration.serviceType,
      locators: declaration.locators,
      providerId: declaration.providerId,
      zkId: declaration.zkId,
      lockedNoteId: declaration.lockedNoteId,
      created: blockHeight,
      active: blockHeight,
      withdrawn: 0'u64,
      nonce: 0'u64,
    ),
  )
  indexEvent(
    registry,
    EventType.created,
    declaration.serviceType,
    blockHeight,
    declarationId,
  )
  ok()

{.pop.}
