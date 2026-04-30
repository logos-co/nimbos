# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Canonical byte encoders for Mantle transaction primitives, payloads, proofs,
## and aggregate transaction structures.
## Spec: [v1.3 Mantle Transaction Encoding](https://nomos-tech.notion.site/v1-3-Mantle-Transaction-Encoding-335261aa09df8051a8a6f325aa41f6a7)

{.push raises: [], gcsafe.}

import ./[primitives, operations, tx_types]
import ../crypto/encoding
export
  encodeByte, encodeEd25519PublicKey, encodeEd25519Signature, encodeFieldElement,
  encodeGroth16, encodeHash32, encodeU16LeLenPrefixed, encodeU32LeLenPrefixed,
  encodeLe, encodeZkPublicKey,
  encodeZkSignature

# -----------------------------------------------------------------------------
# Alias encoders
# -----------------------------------------------------------------------------

func encodeDeclarationId*(value: DeclarationId): array[32, byte] =
  ## DeclarationId = Hash32
  encodeHash32(value)

func encodeChannelId*(value: ChannelId): array[32, byte] =
  ## ChannelId = Hash32
  encodeHash32(value)

func encodeParent*(value: Parent): array[32, byte] =
  ## Parent = Hash32
  encodeHash32(value)

func encodeProviderId*(value: ProviderId): array[32, byte] =
  ## ProviderId = Ed25519PublicKey
  encodeEd25519PublicKey(value)

func encodeZkId*(value: ZkId): array[32, byte] =
  ## ZkId = ZkPublicKey
  encodeZkPublicKey(value)

func encodeSigner*(value: Signer): array[32, byte] =
  ## Signer = Ed25519PublicKey
  encodeEd25519PublicKey(value)

func encodeNoteId*(value: NoteId): array[32, byte] =
  ## NoteId = FieldElement
  encodeFieldElement(value)

func encodeLockedNoteId*(value: LockedNoteId): array[32, byte] =
  ## LockedNoteId = NoteId
  encodeNoteId(value)

func encodeRewardsRoot*(value: RewardsRoot): array[32, byte] =
  ## RewardsRoot = FieldElement
  encodeFieldElement(value)

func encodeVoucherNullifier*(value: VoucherNullifier): array[32, byte] =
  ## VoucherNullifier = FieldElement
  encodeFieldElement(value)

func encodePublicKey*(value: PublicKey): array[32, byte] =
  ## PublicKey = ZkPublicKey
  encodeZkPublicKey(value)

func encodeProofOfClaimProof*(value: ProofOfClaimProof): array[128, byte] =
  ## ProofOfClaimProof = Groth16
  encodeGroth16(value)

# -----------------------------------------------------------------------------
# Numeric value aliases
# -----------------------------------------------------------------------------

func encodeOpcode*(value: Opcode): byte =
  ## Opcode = Byte
  encodeByte(byte(value))

func encodeOpCount*(value: OpCount): byte =
  ## OpCount = Byte
  encodeByte(byte(value))

func encodeExecutionGasPrice*(value: TokenValue): array[8, byte] =
  ## ExecutionGasPrice = UINT64
  encodeLe(uint64(value))

func encodeStorageGasPrice*(value: TokenValue): array[8, byte] =
  ## StorageGasPrice = UINT64
  encodeLe(uint64(value))

func encodeValue*(value: Value): array[8, byte] =
  ## Value = UINT64
  encodeLe(value)

func encodeAmount*(value: Amount): array[8, byte] =
  ## Amount = UINT64
  encodeLe(value)

func encodeNonce*(value: Nonce): array[8, byte] =
  ## Nonce = UINT64
  encodeLe(value)

func encodeOpIdNonce*(value: uint32): array[4, byte] =
  ## OpIdNonce = UINT32
  encodeLe(value)

func encodeMetadata*(value: Metadata): seq[byte] =
  ## Metadata = UINT32 * BYTE
  ## Service-specific node activeness metadata.
  doAssert value.len <= int(high(uint32)),
    "Metadata length exceeds UINT32 range"
  result = @(encodeLe(uint32(value.len)))
  result.add(value)

func encodeSignatureCount*(value: SignatureCount): array[2, byte] =
  ## SignatureCount = UINT16
  encodeLe(uint16(value))

func encodeChannelKeyIndex*(value: ChannelKeyIndex): array[2, byte] =
  ## ChannelKeyIndex = UINT16
  encodeLe(uint16(value))

# -----------------------------------------------------------------------------
# Transfer payload family
# -----------------------------------------------------------------------------

func encodeNote*(value: Note): array[40, byte] =
  ## Note = Value || ZkPublicKey
  let valueBytes = encodeValue(value.value)
  let pubkeyBytes = encodeZkPublicKey(value.zkPublicKey)
  copyMem(addr result[0], unsafeAddr valueBytes[0], 8)
  copyMem(addr result[8], unsafeAddr pubkeyBytes[0], 32)

func encodeInputCount*(value: byte): byte =
  ## InputCount = Byte
  encodeByte(value)

func encodeOutputCount*(value: byte): byte =
  ## OutputCount = Byte
  encodeByte(value)

func encodeInputs*(value: Inputs): seq[byte] =
  ## Inputs = InputCount * NoteId
  doAssert value.noteIds.len <= int(high(byte)),
    "Inputs: InputCount exceeds Byte range"
  result = @[]
  result.add(encodeInputCount(byte(value.noteIds.len)))
  for noteId in value.noteIds:
    result.add(encodeNoteId(noteId))

func encodeInputs*(value: openArray[NoteId]): seq[byte] =
  ## Inputs = InputCount * NoteId
  doAssert value.len <= int(high(byte)),
    "Inputs: InputCount exceeds Byte range"
  result = @[]
  result.add(encodeInputCount(byte(value.len)))
  for noteId in value:
    result.add(encodeNoteId(noteId))

func encodeOutputs*(value: Outputs): seq[byte] =
  ## Outputs = OutputCount * Note
  doAssert value.notes.len <= int(high(byte)),
    "Outputs: OutputCount exceeds Byte range"
  result = @[]
  result.add(encodeOutputCount(byte(value.notes.len)))
  for note in value.notes:
    result.add(encodeNote(note))

func encodeTransfer*(value: TransferPayload): seq[byte] =
  ## Transfer = Inputs || Outputs
  result = encodeInputs(value.inputs)
  result.add(encodeOutputs(value.outputs))

# -----------------------------------------------------------------------------
# Operation payload family
# -----------------------------------------------------------------------------

func encodeInscription*(value: Inscription): seq[byte] =
  ## Inscription = UINT32 * BYTE
  encodeU32LeLenPrefixed(value)

func encodeServiceType*(value: ServiceType): byte =
  ## ServiceType = Byte ; 0 = BN, 1 = DA
  encodeByte(byte(ord(value)))

func encodeLocatorCount*(value: byte): byte =
  ## LocatorCount = Byte
  encodeByte(value)

func encodeLocator*(value: Locator): seq[byte] =
  ## Locator = 2Byte * BYTE ; Max 329 bytes, multiaddr format
  doAssert value.len <= MaxLocatorMultiaddrBytes,
    "Locator exceeds max multiaddr byte length"
  encodeU16LeLenPrefixed(value)

func encodeSdpDeclare*(value: SdpDeclarePayload): seq[byte] =
  ## SDPDeclare = ServiceType LocatorCount *Locator ProviderId ZkId LockedNoteId
  doAssert value.locators.len <= MaxSdpLocators,
    "SDPDeclare LocatorCount exceeds max supported locators"
  result = @[encodeServiceType(value.serviceType)]
  result.add(encodeLocatorCount(byte(value.locators.len)))
  for locator in value.locators:
    result.add(encodeLocator(locator))
  result.add(encodeProviderId(value.providerId))
  result.add(encodeZkId(value.zkId))
  result.add(encodeLockedNoteId(value.lockedNoteId))

func encodeSdpWithdraw*(value: SdpWithdrawPayload): array[72, byte] =
  ## SDPWithdraw = DeclarationId || Nonce || LockedNoteId
  let declarationIdBytes = encodeDeclarationId(value.declarationId)
  let nonceBytes = encodeNonce(value.nonce)
  let lockedNoteIdBytes = encodeLockedNoteId(value.lockedNoteId)
  copyMem(addr result[0], unsafeAddr declarationIdBytes[0], 32)
  copyMem(addr result[32], unsafeAddr nonceBytes[0], 8)
  copyMem(addr result[40], unsafeAddr lockedNoteIdBytes[0], 32)

func encodeSdpActive*(value: SdpActivePayload): seq[byte] =
  ## SDPActive = DeclarationId || Nonce || Metadata
  result = @(encodeDeclarationId(value.declarationId))
  result.add(encodeNonce(value.nonce))
  result.add(encodeMetadata(value.metadata))

func encodeLeaderClaim*(value: LeaderClaimPayload): array[96, byte] =
  ## LeaderClaim = RewardsRoot || VoucherNullifier || PublicKey
  let rootBytes = encodeRewardsRoot(value.rewardsRoot)
  let nullifierBytes = encodeVoucherNullifier(value.voucherNullifier)
  let publicKeyBytes = encodePublicKey(value.publicKey)
  copyMem(addr result[0], unsafeAddr rootBytes[0], 32)
  copyMem(addr result[32], unsafeAddr nullifierBytes[0], 32)
  copyMem(addr result[64], unsafeAddr publicKeyBytes[0], 32)

func encodeChannelWithdraw*(value: ChannelWithdrawPayload): seq[byte] =
  ## ChannelWithdraw = ChannelId || Outputs || OpIdNonce
  result = @(encodeChannelId(value.channel))
  result.add(encodeOutputs(Outputs(notes: value.outputs)))
  result.add(@(encodeOpIdNonce(value.opIdNonce)))

func encodeChannelDeposit*(value: ChannelDepositPayload): seq[byte] =
  ## ChannelDeposit = ChannelId || Inputs || Metadata
  result = @(encodeChannelId(value.channel))
  result.add(encodeInputs(value.inputs))
  result.add(encodeMetadata(value.metadata))

func encodeChannelInscribe*(value: ChannelInscribePayload): seq[byte] =
  ## ChannelInscribe = ChannelId || Inscription || Parent || Signer
  result = @(encodeChannelId(value.channelId))
  result.add(encodeInscription(value.inscription))
  result.add(encodeParent(value.parent))
  result.add(encodeSigner(value.signer))

# -----------------------------------------------------------------------------
# Proof family
# -----------------------------------------------------------------------------

func encodeIndexedEd25519Signature*(
  signature: Ed25519Signature, index: ChannelKeyIndex
): array[66, byte] =
  ## IndexedEd25519Signature = Ed25519Signature || ChannelKeyIndex
  let sigBytes = encodeEd25519Signature(signature)
  let idxBytes = encodeChannelKeyIndex(index)
  copyMem(addr result[0], unsafeAddr sigBytes[0], 64)
  copyMem(addr result[64], unsafeAddr idxBytes[0], 2)

func encodeEd25519SigProof*(value: Ed25519Signature): array[64, byte] =
  ## Ed25519SigProof = Ed25519Signature
  encodeEd25519Signature(value)

func encodeZkSigProof*(value: ZkSignature): array[128, byte] =
  ## ZkSigProof = ZkSignature
  encodeZkSignature(value)

func encodeZkAndEd25519SigsProof*(
  zkSig: ZkSignature, ed25519Sig: Ed25519Signature
): array[192, byte] =
  ## ZkAndEd25519SigsProof = ZkSignature || Ed25519Signature
  let zkBytes = encodeZkSignature(zkSig)
  let edBytes = encodeEd25519Signature(ed25519Sig)
  copyMem(addr result[0], unsafeAddr zkBytes[0], 128)
  copyMem(addr result[128], unsafeAddr edBytes[0], 64)

func encodeChannelWithdrawOpProof*(
  signatures: openArray[Ed25519Signature], indexes: openArray[ChannelKeyIndex]
): seq[byte] =
  ## ChannelWithdrawOpProof = SignatureCount * IndexedEd25519Signature
  doAssert signatures.len == indexes.len,
    "ChannelWithdrawOpProof: signatures and indexes length mismatch"
  doAssert signatures.len <= int(high(uint16)),
    "ChannelWithdrawOpProof: too many signatures for UINT16 SignatureCount"
  for i in 1 ..< indexes.len:
    doAssert uint16(indexes[i - 1]) < uint16(indexes[i]),
      "ChannelWithdrawOpProof: indexes must be strictly increasing (ordered, no duplicates)"

  result = @[]
  let countBytes = encodeSignatureCount(SignatureCount(uint16(signatures.len)))
  result.add(countBytes[0])
  result.add(countBytes[1])
  for i in 0 ..< signatures.len:
    let indexedSig = encodeIndexedEd25519Signature(signatures[i], indexes[i])
    result.add(indexedSig)

func encodeOpProof*(proof: OpProof): seq[byte] =
  ## OpProof =
  ##   Ed25519SigProof /
  ##   ZkSigProof /
  ##   ZkAndEd25519SigsProof /
  ##   ChannelWithdrawOpProof /
  ##   ProofOfClaimProof
  ##
  ## Additional local variants:
  ## - opfChannelDeposit: ZkSigProof
  ## - opfChannelConfig: encoded as SignatureCount * IndexedEd25519Signature
  case proof.kind
  of opfChannelInscribe:
    @(encodeEd25519SigProof(proof.ed25519SigProof))
  of opfTransfer:
    @(encodeZkSigProof(proof.transferProof))
  of opfSdpWithdraw:
    @(encodeZkSigProof(proof.sdpWithdrawProof))
  of opfSdpActive:
    @(encodeZkSigProof(proof.sdpActiveProof))
  of opfSdpDeclare:
    @(encodeZkAndEd25519SigsProof(
      proof.declarationProof.zkSig, proof.declarationProof.ed25519Sig
    ))
  of opfChannelWithdraw:
    encodeChannelWithdrawOpProof(
      proof.channelWithdrawOpProof.signatures, proof.channelWithdrawOpProof.indexes
    )
  of opfLeaderClaim:
    @(encodeProofOfClaimProof(proof.proofOfClaimProof))
  of opfChannelConfig:
    encodeChannelWithdrawOpProof(
      proof.channelConfigOpProof.signatures, proof.channelConfigOpProof.indexes
    )
  of opfChannelDeposit:
    @(encodeZkSigProof(proof.channelDepositProof))

func encodeOpsProofs*(ops: openArray[Op], proofs: openArray[OpProof]): seq[byte] =
  ## OpsProofs = *OpProof
  ## 1. Length must be <= OpCount.
  ## 2. type(OpProofs[i]) == ProofFor(Op[i]) for provided proofs.
  doAssert proofs.len <= ops.len,
    "OpsProofs length must be <= OpCount"
  result = @[]
  for i in 0 ..< proofs.len:
    doAssert proofs[i].kind == expectedOpProofKindForOpcode(ops[i].opcode),
      "OpProof variant does not match corresponding Op"
    let encoded = encodeOpProof(proofs[i])
    result.add(encoded)

# -----------------------------------------------------------------------------
# Operation aggregate encoders
# -----------------------------------------------------------------------------

func encodeOpPayload*(payload: OpPayload): seq[byte] =
  ## OpPayload = Transfer /
  ##             ChannelInscribe /
  ##             ChannelDeposit /
  ##             ChannelWithdraw /
  ##             SDPDeclare /
  ##             SDPWithdraw /
  ##             SDPActive /
  ##             LeaderClaim
  case payload.kind
  of Transfer:
    encodeTransfer(payload.transfer)
  of ChannelInscribe:
    encodeChannelInscribe(payload.channelInscribe)
  of ChannelDeposit:
    encodeChannelDeposit(payload.channelDeposit)
  of ChannelWithdraw:
    @(encodeChannelWithdraw(payload.channelWithdraw))
  of SdpDeclare:
    encodeSdpDeclare(payload.sdpDeclare)
  of SdpWithdraw:
    @(encodeSdpWithdraw(payload.sdpWithdraw))
  of SdpActive:
    encodeSdpActive(payload.sdpActive)
  of LeaderClaim:
    @(encodeLeaderClaim(payload.leaderClaim))
  of ChannelConfig:
    ## Not part of the provided OpPayload encoding variant list.
    @[]

func encodeOp*(op: Op): seq[byte] =
  ## Op = Opcode || OpPayload
  result = @[encodeOpcode(op.opcode)]
  result.add(encodeOpPayload(op.payload))

func encodeOps*(ops: openArray[Op]): seq[byte] =
  ## Ops = OpCount * Op
  doAssert ops.len <= int(high(uint8)),
    "Ops length exceeds OpCount byte range"
  result = @[encodeOpCount(OpCount(uint8(ops.len)))]
  for op in ops:
    result.add(encodeOp(op))

# -----------------------------------------------------------------------------
# Transaction encoders
# -----------------------------------------------------------------------------

func encodeMantleTx*(tx: MantleTx): seq[byte] =
  ## MantleTx = Ops || ExecutionGasPrice || StorageGasPrice
  result = encodeOps(tx.ops)
  result.add(encodeExecutionGasPrice(tx.executionGasPrice))
  result.add(encodeStorageGasPrice(tx.permanentStorageGasPrice))

func encodeSignedMantleTx*(signedTx: SignedMantleTx): seq[byte] =
  ## SignedMantleTx = MantleTx || OpsProofs
  result = encodeMantleTx(signedTx.tx)
  result.add(encodeOpsProofs(signedTx.tx.ops, signedTx.opProofs))

{.pop.}
