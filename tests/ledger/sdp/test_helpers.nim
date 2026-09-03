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
  ../../../logos_chain/core/crypto/[hashing, types],
  ../../../logos_chain/core/mantle/[operations, proofs, utxo],
  ../../../logos_chain/ledger/[channel_notes, utxo_store],
  ../../../logos_chain/zk/poseidon2/hasher,
  ../../../logos_chain/deployment/deployment_settings as deploy,
  ./test_utxo_helpers

export ops, utxo, utxo_store, operations, channel_notes

# Devnet-shaped reward parameters; two providers is the smallest network
# that can freeze a target epoch.
const testBlendRewardsParams = BlendRewardsParams(
  roundsPerEpoch: 6000,
  messageFrequencyPerRound: 1.0,
  numBlendLayers: 4,
  dataReplicationFactor: 0,
  minimumNetworkSize: 2,
  activityThresholdSensitivity: 1)

# The quota circuit compares 20-bit integers, so the computed core quota
# must stay below 2^20 or the rotation forfeits the target. At 2^18
# rounds the quota is 2^19 for two providers and 349526 for three. The
# token count reaches 2^20, so chi = 21, the digest is 3 bytes, and the
# threshold is 21 - 2 = 19 of 24 bits. An honest token fails the lottery
# with probability ~7.7e-4. The inputs are fixed, so every outcome below
# is deterministic and was checked at generation time. All float products
# stay under 2^21, well inside exact double range.
const testBlendLotteryParams* = BlendRewardsParams(
  roundsPerEpoch: 1'u64 shl 18,
  messageFrequencyPerRound: 1.0,
  numBlendLayers: 4,
  dataReplicationFactor: 0,
  minimumNetworkSize: 2,
  activityThresholdSensitivity: 0)

func testSdpConfig*(): deploy.SdpConfig =
  deploy.SdpConfig(
    bn: deploy.BnServiceParams(inactivityPeriod: 2, epoch: 0),
    minStake: deploy.MinStake(threshold: 100, epoch: 0),
  )

func testSdpRegistry*(): SdpRegistry =
  SdpRegistry.init(testSdpConfig(), testBlendRewardsParams)

func testPoqChain*(): PoqChainContext =
  ## Arbitrary epoch-frozen chain values. Only the real-verifier tests
  ## need values a proof was actually generated against.
  PoqChainContext(
    polLedgerAged: frFromBytesLE([byte 21]).get,
    polEpochNonce: frFromBytesLE([byte 22]).get,
    lottery0: frFromBytesLE([byte 23]).get,
    lottery1: frFromBytesLE([byte 24]).get,
    powBlendDifficulty: frFromBytesLE([byte 25]).get)

func acceptAllPoq*(
    proofOfQuota: ProofOfQuota, signingKey: Ed25519PublicKey,
    public: PoqPublic
): Result[bool, PoqLoadError] =
  ## Permissive stub for tests that exercise everything but the Groth16
  ## check. Production callers use the real verifier.
  ok(true)

func rejectAllPoq*(
    proofOfQuota: ProofOfQuota, signingKey: Ed25519PublicKey,
    public: PoqPublic
): Result[bool, PoqLoadError] =
  ## Rejecting stub for tests that assert the quota check gates the path.
  ok(false)

proc findRho*(index, membership: uint64): FieldElement =
  ## Smallest fe(k) whose selection index is `index`. One in `membership`
  ## candidates matches, so the bound is never reached in practice.
  for k in 1'u64 .. 10_000'u64:
    let rho = frFromBytesLE(encodeLe(k)).get
    if expectedSelectionIndex(rho, membership) == index:
      return rho
  doAssert false, "no selection randomness found for the requested index"

proc mkActivity*(
    rho: FieldElement, epoch: EpochNumber, keySeed: byte
): ActivityProof =
  ## Activity proof whose nullifier binds to `rho`, as the circuit requires.
  var
    proof = ActivityProof(
      epoch: epoch,
      proofOfQuota: ProofOfQuota(
        keyNullifier: Poseidon2Hasher.compress(KeyNullifierDomainFr, rho)),
      proofOfSelection: rho)
    keyBytes: array[32, byte]
  keyBytes[0] = keySeed
  doAssert proof.signingKey.init(keyBytes)
  proof

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
    acceptAllPoq,
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
