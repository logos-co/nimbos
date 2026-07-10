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
  ../../../logos_chain/core/sdp/ops/util,
  ../../../logos_chain/core/sdp/[registry, state, ops],
  ../../../logos_chain/core/crypto/types,
  ../../../logos_chain/core/mantle/[operations, proofs, utxo],
  ../../../logos_chain/ledger/utxo_store,
  ../../../logos_chain/zk/poseidon2/hasher,
  ../../../logos_chain/deployment/deployment_settings as deploy,
  ./test_utxo_helpers

export ops, utxo, utxo_store, operations

const TestSecurityParam* = 1'u64

func testSdpConfig*(): deploy.SdpConfig =
  deploy.SdpConfig(
    bn: deploy.BnServiceParams(
      lockPeriod: 5, inactivityPeriod: 1, retentionPeriod: 1, epoch: 0,
    ),
    minStake: deploy.MinStake(threshold: 100, timestamp: 0),
  )

func testSdpRegistry*(): SdpRegistry =
  SdpRegistry.init(testSdpConfig(), TestSecurityParam)

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
    blockHeight: BlockNumber,
): DeclarationId =
  let declarationId = declarationId(declaration)
  let params = getParametersAt(registry, declaration.serviceType, blockHeight).valueOr:
    defaultBnServiceParameters()
  let lockPeriod = params.lockPeriod
  registry.state = insertDeclaration(
    addDeclarationToLockedNote(
      registry.state,
      declaration.lockedNoteId,
      declarationId,
      blockHeight + lockPeriod,
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
  declarationId

proc installTestActive*(
    registry: var SdpRegistry,
    active: ActiveMessage,
    blockHeight: BlockNumber,
) =
  var updated = registry.state.declarations.getOrDefault(active.declarationId)
  updated.nonce = active.nonce
  updated.active = blockHeight
  registry.state = insertDeclaration(
    registry.state, active.declarationId, updated,
  )

proc installTestWithdraw*(
    registry: var SdpRegistry,
    withdraw: WithdrawMessage,
    blockHeight: BlockNumber,
) =
  var declaration = registry.state.declarations.getOrDefault(withdraw.declarationId)
  declaration.nonce = withdraw.nonce
  declaration.withdrawn = blockHeight
  registry.state = removeDeclarationFromLockedNote(
    insertDeclaration(registry.state, withdraw.declarationId, declaration),
    withdraw.lockedNoteId,
    withdraw.declarationId,
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
    registry: var SdpRegistry,
    declaration: DeclarationMessage,
    store: UtxoStore,
    height: BlockNumber,
): Result[void, LedgerError] =
  tryApplySdpDeclare(
    registry,
    declaration,
    defaultDeclareProof(),
    mkTxHash(),
    store,
    height,
  )

proc execWithdraw*(
    seeded: var SeededDeclaration,
    withdraw: WithdrawMessage,
    height: BlockNumber,
): Result[void, LedgerError] =
  tryApplySdpWithdraw(
    seeded.registry,
    withdraw,
    defaultWithdrawProof(),
    mkTxHash(),
    seeded.store,
    height,
  )

proc execActive*(
    seeded: var SeededDeclaration,
    active: ActiveMessage,
    height: BlockNumber,
): Result[void, LedgerError] =
  tryApplySdpActive(
    seeded.registry,
    active,
    defaultActiveProof(),
    mkTxHash(),
    height,
  )

proc seedDeclaration*(
    pkSeed: byte = 1, declareHeight: BlockNumber = 10,
): SeededDeclaration =
  let utxo = mkUtxo(value = 200, pkSeed = pkSeed)
  var store = UtxoStore.init()
  store = store.insert(utxo.id, utxo).store
  let declaration = DeclarationMessage(
    serviceType: ServiceType.bn,
    locators: @[mkLocator(30303)],
    providerId: mkProvider(1),
    lockedNoteId: utxo.id,
    zkId: utxo.note.zkPublicKey,
  )
  var registry = testSdpRegistry()
  let declId = installTestDeclaration(registry, declaration, declareHeight)
  SeededDeclaration(
    registry: registry, store: store, declaration: declaration, declId: declId,
  )

{.pop.}
