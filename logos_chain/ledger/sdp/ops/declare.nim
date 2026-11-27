# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP Declare validation and application.
## Spec: [Service Declaration Protocol v1.8.0](https://github.com/logos-co/logos-lips/blob/bd1ca2c881ae94606d4ab23af1255fd922e85dd6/docs/blockchain/raw/bedrock-service-declaration-protocol.md)

{.push raises: [], gcsafe.}

import
  ./util,
  ../[registry, state],
  ../../[channel_notes, utxo_store],
  ../../../core/mantle/[operations, proofs]

export util, registry, state

func validateSdpDeclareState*(
    declaration: DeclarationMessage,
    minStake: TokenValue,
    utxos: UtxoStore,
    channelNotes: ChannelNotes,
    state: SdpState,
): Result[ZkPublicKey, LedgerError] =
  ## State checks for SdpDeclare; returns the service note's public key for
  ## the proof step.
  if lockedNoteHasService(state, declaration.lockedNoteId, declaration.serviceType):
    return err(LockedNoteServiceConflict)

  # Channel notes back their channel's bridged funds; they may participate in
  # PoS but never serve as service-declaration collateral.
  if channelNotes.isChannelNote(declaration.lockedNoteId):
    return err(ChannelNoteSpend)

  let
    utxo = utxos.get(declaration.lockedNoteId).valueOr:
      return err(LockedNoteNotFound)
    note = utxo.note

  if note.value < minStake:
    return err(InsufficientStake)

  if declarationId(declaration) in state.declarations:
    return err(DuplicateDeclaration)

  if hasProvider(state, declaration.serviceType, declaration.providerId):
    return err(DuplicateProviderId)

  ok(note.zkPublicKey)

proc applySdpDeclare*(
    registry: sink SdpRegistry,
    declaration: DeclarationMessage,
    epoch: EpochNumber,
): Result[SdpRegistry, LedgerError] =
  ## Mutation only; assumes validation passed.
  if getParametersAt(registry, declaration.serviceType, epoch).isNone:
    return err(MissingServiceParameters)
  let declarationId = declarationId(declaration)
  registry.state = insertDeclaration(
    addDeclarationToLockedNote(
      registry.state,
      declaration.lockedNoteId,
      declarationId,
    ),
    declarationId,
    DeclarationInfo(
      service: declaration.serviceType,
      locators: declaration.locators,
      providerId: declaration.providerId,
      zkId: declaration.zkId,
      lockedNoteId: declaration.lockedNoteId,
      created: epoch,
      active: Opt.none(EpochNumber),
      withdrawAt: Opt.none(EpochNumber),
      nonce: Nonce(lifecycleEpoch: epoch, sequence: 0),
    ),
  )
  ok(registry)

proc tryApplySdpDeclare*(
    registry: sink SdpRegistry,
    declaration: DeclarationMessage,
    proof: ZkAndEd25519SigsProof,
    txHash: ZkHash,
    utxos: UtxoStore,
    channelNotes: ChannelNotes,
    epoch: EpochNumber,
): Result[SdpRegistry, LedgerError] =
  let notePk = ?validateSdpDeclareState(
    declaration, registry.params.minStake, utxos, channelNotes, registry.state)
  ?verifyZkSig(proof.zkSig, txHash, [notePk, declaration.zkId])
  applySdpDeclare(registry, declaration, epoch)

{.pop.}
