# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  results,
  libp2p/[crypto/ed25519/ed25519, multiaddress],
  ../../../logos_chain/ledger/sdp/ops/util,
  ../../../logos_chain/ledger/sdp/[registry, ops, state],
  ../../../logos_chain/core/crypto/types,
  ../../../logos_chain/core/mantle/[operations, proofs, utxo],
  ../../../logos_chain/ledger/[channel_notes, utxo_store],
  ../../../logos_chain/zk/poseidon2/hasher,
  ../../../logos_chain/deployment/deployment_settings as deploy,
  ./test_utxo_helpers

export ops, utxo, utxo_store, operations, channel_notes

func testSdpConfig*(): deploy.SdpConfig =
  deploy.SdpConfig(
    bn: deploy.BnServiceParams(inactivityPeriod: 2, epoch: 0),
    minStake: deploy.MinStake(threshold: 100, epoch: 0),
  )

func testSdpRegistry*(): SdpRegistry =
  SdpRegistry.init(testSdpConfig())

proc mkProvider*(seed: byte): ProviderId =
  var bytes: array[EdPublicKeySize, byte]
  bytes[0] = seed
  var key: ProviderId
  doAssert key.init(bytes)
  key

proc mkLocator*(port: int): Locator =
  MultiAddress.init("/ip4/127.0.0.1/tcp/" & $port).get()

proc installTestDeclaration*(
    registry: var SdpRegistry,
    declaration: DeclarationMessage,
    epoch: EpochNumber,
): DeclarationId =
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
  declarationId

proc installTestActive*(
    registry: var SdpRegistry,
    active: ActiveMessage,
    epoch: EpochNumber,
) =
  var updated = registry.state.declarations.getOrDefault(active.declarationId)
  updated.nonce = active.nonce
  updated.active = Opt.some(epoch)
  registry.state = insertDeclaration(
    registry.state, active.declarationId, updated,
  )

proc installTestWithdraw*(
    registry: var SdpRegistry,
    withdraw: WithdrawMessage,
    epoch: EpochNumber,
) =
  var declaration = registry.state.declarations.getOrDefault(withdraw.declarationId)
  declaration.nonce = withdraw.nonce
  declaration.withdrawAt = Opt.some(epoch)
  registry.state = insertDeclaration(
    registry.state, withdraw.declarationId, declaration,
  )

func mkTxHash*(seed: byte = 0x42): ZkHash =
  var h: ZkHash
  h[0] = seed
  h

func defaultDeclareProof(): ZkAndEd25519SigsProof =
  defaultOpProofForOpcode(OpSdpDeclare).declarationProof

func defaultWithdrawProof(): ZkSigProof =
  defaultOpProofForOpcode(OpSdpWithdraw).sdpWithdrawProof

func defaultActiveProof(): ZkSigProof =
  defaultOpProofForOpcode(OpSdpActive).sdpActiveProof

type SeededDeclaration* = object
  registry*: SdpRegistry
  store*: UtxoStore
  declaration*: DeclarationMessage
  declId*: DeclarationId

proc execDeclare*(
    registry: sink SdpRegistry,
    declaration: DeclarationMessage,
    store: UtxoStore,
    epoch: EpochNumber,
    channelNotes = ChannelNotes.init(),
): Result[SdpRegistry, LedgerError] =
  tryApplySdpDeclare(
    registry,
    declaration,
    defaultDeclareProof(),
    mkTxHash(),
    store,
    channelNotes,
    epoch,
  )

proc execWithdraw*(
    seeded: sink SeededDeclaration,
    withdraw: WithdrawMessage,
    epoch: EpochNumber,
): Result[SdpRegistry, LedgerError] =
  tryApplySdpWithdraw(
    seeded.registry,
    withdraw,
    defaultWithdrawProof(),
    mkTxHash(),
    seeded.store,
    epoch,
  )

proc execActive*(
    seeded: sink SeededDeclaration,
    active: ActiveMessage,
    epoch: EpochNumber,
): Result[SdpRegistry, LedgerError] =
  tryApplySdpActive(
    seeded.registry,
    active,
    defaultActiveProof(),
    mkTxHash(),
    epoch,
  )

proc seedDeclaration*(
    pkSeed: byte = 1, declareEpoch: EpochNumber = 10,
): SeededDeclaration =
  let utxo = mkUtxo(value = 200, pkSeed = pkSeed)
  var store = UtxoStore.init()
  store = store.insert(utxo.id, utxo).store
  let declaration = DeclarationMessage(
    serviceType: ServiceType.bn,
    locators: @[mkLocator(30303)],
    providerId: mkProvider(pkSeed),
    lockedNoteId: utxo.id,
    zkId: utxo.note.zkPublicKey,
  )
  var registry = testSdpRegistry()
  let declId = installTestDeclaration(registry, declaration, declareEpoch)
  SeededDeclaration(
    registry: registry, store: store, declaration: declaration, declId: declId,
  )

{.pop.}
