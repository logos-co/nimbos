# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP Declare validation and application.
## Spec: [1.1.0 Service Declaration Protocol](https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/bedrock-service-declaration-protocol.md)

{.push raises: [], gcsafe.}

import
  results,
  std/sequtils,
  libp2p/crypto/ed25519/ed25519,
  ./util,
  ../[registry, state],
  ../../[channel_notes, utxo_store],
  ../../../core/crypto/types,
  ../../../core/mantle/[operations, proofs]

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
    channelNotes: ChannelNotes,
    state: SdpState,
): Result[void, LedgerError] =
  if declaration.locators.len == 0:
    return err(EmptyLocators)
  if declaration.locators.len > MaxSdpLocators:
    return err(TooManyLocators)
  if not declaration.locators.allIt(isValidLocator(it)):
    return err(InvalidLocator)

  if lockedNoteHasService(state, declaration.lockedNoteId, declaration.serviceType):
    return err(LockedNoteServiceConflict)

  # Channel notes back their channel's bridged funds; they may participate in
  # PoS but never serve as service-declaration collateral.
  if channelNotes.isChannelNote(declaration.lockedNoteId):
    return err(ChannelNoteSpend)

  let utxo = utxos.get(declaration.lockedNoteId).valueOr:
    return err(LockedNoteNotFound)
  let note = utxo.note

  if note.value < minStake.stakeThreshold:
    return err(InsufficientStake)

  let declarationId = declarationId(declaration)
  if declarationId in state.declarations:
    return err(DuplicateDeclaration)

  ?verifySdpDeclareProofs(
    declaration, proof, txHash, note.zkPublicKey,
  )

  ok()

proc applySdpDeclare*(
    registry: sink SdpRegistry,
    declaration: DeclarationMessage,
    epoch: EpochNumber,
): Result[SdpRegistry, LedgerError] =
  ## Mutation only; assumes validation passed (or genesis trusted the op).
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
      nonce: 0'u64,
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
  let minStake = getMinStakeAt(registry, epoch).valueOr:
    return err(MinStakeNotFound)
  ?validateSdpDeclare(
    declaration, proof, txHash, minStake, utxos, channelNotes, registry.state,
  )
  applySdpDeclare(registry, declaration, epoch)

{.pop.}
