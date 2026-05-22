# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

## Canonical byte decoders for Mantle transaction primitives, payloads, proofs,
## and aggregate transaction structures (inverse of ``tx_encoding``).
## Spec: [v1.3 Mantle Transaction Encoding](https://nomos-tech.notion.site/v1-3-Mantle-Transaction-Encoding-335261aa09df8051a8a6f325aa41f6a7)

{.push raises: [], gcsafe.}

import ./[primitives, operations, tx_types]
import ../crypto/decoding
import libp2p/crypto/ed25519/ed25519
export
  decodeByte, decodeEd25519PublicKey, decodeEd25519Signature, decodeFieldElement,
  decodeFieldElementAt,
  decodeGroth16, decodeHash32, decodeU16LeLenPrefixed, decodeU32LeLenPrefixed,
  decodeZkPublicKey, decodeZkSignature


func decodeDeclarationId*(data: openArray[byte]): DeclarationId {.raises: [DecodingError].} =
  decodeHash32(data)

func decodeChannelId*(data: openArray[byte]): ChannelId {.raises: [DecodingError].} =
  decodeHash32(data)

func decodeParent*(data: openArray[byte]): Parent {.raises: [DecodingError].} =
  decodeHash32(data)

func decodeProviderId*(data: openArray[byte]): ProviderId {.raises: [DecodingError].} =
  decodeEd25519PublicKey(data)

func decodeZkId*(data: openArray[byte]): ZkId {.raises: [DecodingError].} =
  decodeZkPublicKey(data)

func decodeSigner*(data: openArray[byte]): Signer {.raises: [DecodingError].} =
  decodeEd25519PublicKey(data)

func decodeNoteId*(data: openArray[byte]): NoteId {.raises: [DecodingError].} =
  decodeFieldElement(data)

func decodeLockedNoteId*(data: openArray[byte]): LockedNoteId {.raises: [DecodingError].} =
  decodeNoteId(data)

func decodeRewardsRoot*(data: openArray[byte]): RewardsRoot {.raises: [DecodingError].} =
  decodeFieldElement(data)

func decodeVoucherNullifier*(data: openArray[byte]): VoucherNullifier {.raises: [DecodingError].} =
  decodeFieldElement(data)

func decodePublicKey*(data: openArray[byte]): PublicKey {.raises: [DecodingError].} =
  decodeZkPublicKey(data)

func decodeProofOfClaimProof*(data: openArray[byte]): ProofOfClaimProof {.raises: [DecodingError].} =
  decodeGroth16(data)


func decodeOpcode*(data: openArray[byte]): Opcode {.raises: [DecodingError].} =
  Opcode(decodeByte(data))

func decodeOpCount*(data: openArray[byte]): OpCount {.raises: [DecodingError].} =
  OpCount(decodeByte(data))

func decodeExecutionGasPrice*(data: openArray[byte]): TokenValue {.raises: [DecodingError].} =
  var pos = 0
  result = TokenValue(readLe[uint64](data, pos))
  finishDecode(data, pos)

func decodeStorageGasPrice*(data: openArray[byte]): TokenValue {.raises: [DecodingError].} =
  decodeExecutionGasPrice(data)

func decodeValue*(data: openArray[byte]): Value {.raises: [DecodingError].} =
  var pos = 0
  result = readLe[uint64](data, pos)
  finishDecode(data, pos)

func decodeAmount*(data: openArray[byte]): Amount {.raises: [DecodingError].} =
  decodeValue(data)

func decodeNonce*(data: openArray[byte]): Nonce {.raises: [DecodingError].} =
  decodeValue(data)

func decodeOpIdNonce*(data: openArray[byte]): uint32 {.raises: [DecodingError].} =
  var pos = 0
  result = readLe[uint32](data, pos)
  finishDecode(data, pos)

func decodeMetadata*(data: openArray[byte]): Metadata {.raises: [DecodingError].} =
  decodeU32LeLenPrefixed(data)

func decodeSignatureCount*(data: openArray[byte]): SignatureCount {.raises: [DecodingError].} =
  var pos = 0
  result = SignatureCount(readLe[uint16](data, pos))
  finishDecode(data, pos)

func decodeChannelKeyIndex*(data: openArray[byte]): ChannelKeyIndex {.raises: [DecodingError].} =
  var pos = 0
  result = ChannelKeyIndex(readLe[uint16](data, pos))
  finishDecode(data, pos)


proc readNote(data: openArray[byte], pos: var int): Note {.raises: [DecodingError].} =
  let value = Value(readLe[uint64](data, pos))
  let zkPublicKey = decodeFieldElementAt(data, pos)
  Note(value: value, zkPublicKey: zkPublicKey)

proc readInputs(data: openArray[byte], pos: var int): Inputs {.raises: [DecodingError].} =
  let count = readByte(data, pos)
  var noteIds = newSeqOfCap[NoteId](count)
  for _ in 0 ..< int(count):
    noteIds.add decodeFieldElementAt(data, pos)
  Inputs(noteIds: noteIds)

proc readOutputs(data: openArray[byte], pos: var int): Outputs {.raises: [DecodingError].} =
  let count = readByte(data, pos)
  var notes = newSeqOfCap[Note](count)
  for _ in 0 ..< int(count):
    notes.add readNote(data, pos)
  Outputs(notes: notes)

func decodeNote*(data: openArray[byte]): Note {.raises: [DecodingError].} =
  var pos = 0
  result = readNote(data, pos)
  finishDecode(data, pos)

func decodeInputCount*(data: openArray[byte]): byte {.raises: [DecodingError].} =
  decodeByte(data)

func decodeOutputCount*(data: openArray[byte]): byte {.raises: [DecodingError].} =
  decodeByte(data)

func decodeInputs*(data: openArray[byte]): Inputs {.raises: [DecodingError].} =
  var pos = 0
  result = readInputs(data, pos)
  finishDecode(data, pos)

func decodeInputsNoteIds*(data: openArray[byte]): seq[NoteId] {.raises: [DecodingError].} =
  decodeInputs(data).noteIds

func decodeOutputs*(data: openArray[byte]): Outputs {.raises: [DecodingError].} =
  var pos = 0
  result = readOutputs(data, pos)
  finishDecode(data, pos)

func decodeTransfer*(data: openArray[byte]): TransferPayload {.raises: [DecodingError].} =
  var pos = 0
  let inputs = readInputs(data, pos)
  let outputs = readOutputs(data, pos)
  finishDecode(data, pos)
  TransferPayload(inputs: inputs, outputs: outputs)


func decodeInscription*(data: openArray[byte]): Inscription {.raises: [DecodingError].} =
  decodeU32LeLenPrefixed(data)

proc readServiceType(data: openArray[byte], pos: var int): ServiceType {.raises: [DecodingError].} =
  let b = readByte(data, pos)
  case b
  of byte(ord(bn)):
    bn
  else:
    raise newException(DecodingError, "invalid ServiceType byte: " & $b)

func decodeServiceType*(data: openArray[byte]): ServiceType {.raises: [DecodingError].} =
  var pos = 0
  result = readServiceType(data, pos)
  finishDecode(data, pos)

func decodeLocatorCount*(data: openArray[byte]): byte {.raises: [DecodingError].} =
  decodeByte(data)

proc readLocator(data: openArray[byte], pos: var int): Locator {.raises: [DecodingError].} =
  let raw = readU16LeLenPrefixed(data, pos)
  if raw.len > MaxLocatorMultiaddrBytes:
    raise newException(DecodingError, "Locator exceeds max multiaddr byte length")
  raw

func decodeLocator*(data: openArray[byte]): Locator {.raises: [DecodingError].} =
  var pos = 0
  result = readLocator(data, pos)
  finishDecode(data, pos)

func decodeSdpDeclare*(data: openArray[byte]): SdpDeclarePayload {.raises: [DecodingError].} =
  var pos = 0
  let serviceType = readServiceType(data, pos)
  let locatorCount = readByte(data, pos)
  if locatorCount > MaxSdpLocators:
    raise newException(DecodingError, "SDPDeclare LocatorCount exceeds max supported locators")
  var locators = newSeqOfCap[Locator](locatorCount)
  for _ in 0 ..< int(locatorCount):
    locators.add readLocator(data, pos)
  var providerKey: Ed25519PublicKey
  if not providerKey.init(readFixed[EdPublicKeySize](data, pos)):
    raise newException(DecodingError, "invalid ProviderId bytes")
  let zkId = decodeFieldElementAt(data, pos)
  let lockedNoteId = decodeFieldElementAt(data, pos)
  finishDecode(data, pos)
  SdpDeclarePayload(
    serviceType: serviceType,
    locators: locators,
    providerId: providerKey,
    zkId: zkId,
    lockedNoteId: lockedNoteId,
  )

func decodeSdpWithdraw*(data: openArray[byte]): SdpWithdrawPayload {.raises: [DecodingError].} =
  var pos = 0
  let declarationId = readFixed[32](data, pos)
  let nonce = readLe[uint64](data, pos)
  let lockedNoteId = decodeFieldElementAt(data, pos)
  finishDecode(data, pos)
  SdpWithdrawPayload(
    declarationId: declarationId,
    nonce: nonce,
    lockedNoteId: lockedNoteId,
  )

func decodeSdpActive*(data: openArray[byte]): SdpActivePayload {.raises: [DecodingError].} =
  var pos = 0
  let declarationId = readFixed[32](data, pos)
  let nonce = readLe[uint64](data, pos)
  let metadata = readU32LeLenPrefixed(data, pos)
  finishDecode(data, pos)
  SdpActivePayload(
    declarationId: declarationId,
    nonce: nonce,
    metadata: metadata,
  )

func decodeLeaderClaim*(data: openArray[byte]): LeaderClaimPayload {.raises: [DecodingError].} =
  var pos = 0
  let rewardsRoot = decodeFieldElementAt(data, pos)
  let voucherNullifier = decodeFieldElementAt(data, pos)
  let publicKey = decodeFieldElementAt(data, pos)
  finishDecode(data, pos)
  LeaderClaimPayload(
    rewardsRoot: rewardsRoot,
    voucherNullifier: voucherNullifier,
    publicKey: publicKey,
  )

func decodeChannelWithdraw*(data: openArray[byte]): ChannelWithdrawPayload {.raises: [DecodingError].} =
  var pos = 0
  let channel = readFixed[32](data, pos)
  let outputs = readOutputs(data, pos)
  let opIdNonce = readLe[uint32](data, pos)
  finishDecode(data, pos)
  ChannelWithdrawPayload(
    channel: channel,
    outputs: outputs.notes,
    opIdNonce: opIdNonce,
  )

func decodeChannelDeposit*(data: openArray[byte]): ChannelDepositPayload {.raises: [DecodingError].} =
  var pos = 0
  let channel = readFixed[32](data, pos)
  let count = readByte(data, pos)
  var inputs = newSeqOfCap[NoteId](count)
  for _ in 0 ..< int(count):
    inputs.add decodeFieldElementAt(data, pos)
  let metadata = readU32LeLenPrefixed(data, pos)
  finishDecode(data, pos)
  ChannelDepositPayload(channel: channel, inputs: inputs, metadata: metadata)

func decodeChannelInscribe*(data: openArray[byte]): ChannelInscribePayload {.raises: [DecodingError].} =
  var pos = 0
  let channelId = readFixed[32](data, pos)
  let inscription = readU32LeLenPrefixed(data, pos)
  let parent = readFixed[32](data, pos)
  var signerKey: Ed25519PublicKey
  if not signerKey.init(readFixed[EdPublicKeySize](data, pos)):
    raise newException(DecodingError, "invalid Signer bytes")
  finishDecode(data, pos)
  ChannelInscribePayload(
    channelId: channelId,
    inscription: inscription,
    parent: parent,
    signer: signerKey,
  )


proc readEd25519Signature(data: openArray[byte], pos: var int): Ed25519Signature {.raises: [DecodingError].} =
  var sig: Ed25519Signature
  if not sig.init(readFixed[EdSignatureSize](data, pos)):
    raise newException(DecodingError, "invalid Ed25519 signature bytes")
  sig

proc readIndexedEd25519Signature(data: openArray[byte], pos: var int): (Ed25519Signature, ChannelKeyIndex) {.raises: [DecodingError].} =
  let signature = readEd25519Signature(data, pos)
  let index = ChannelKeyIndex(readLe[uint16](data, pos))
  (signature, index)

func decodeEd25519SigProof*(data: openArray[byte]): Ed25519Signature {.raises: [DecodingError].} =
  decodeEd25519Signature(data)

func decodeZkSigProof*(data: openArray[byte]): ZkSignature {.raises: [DecodingError].} =
  decodeZkSignature(data)

func decodeZkAndEd25519SigsProof*(data: openArray[byte]): ZkAndEd25519SigsProof {.raises: [DecodingError].} =
  var pos = 0
  let zkSig = readFixed[128](data, pos)
  let ed25519Sig = readEd25519Signature(data, pos)
  finishDecode(data, pos)
  ZkAndEd25519SigsProof(zkSig: zkSig, ed25519Sig: ed25519Sig)

proc readChannelWithdrawOpProof(data: openArray[byte], pos: var int): ChannelWithdrawOpProof {.raises: [DecodingError].} =
  let count = SignatureCount(readLe[uint16](data, pos))
  var signatures = newSeqOfCap[Ed25519Signature](count)
  var indexes = newSeqOfCap[ChannelKeyIndex](count)
  var prevIndex = ChannelKeyIndex(0)
  var havePrev = false
  for _ in 0 ..< int(count):
    let (signature, index) = readIndexedEd25519Signature(data, pos)
    if havePrev and uint16(index) <= uint16(prevIndex):
      raise newException(DecodingError, "ChannelWithdrawOpProof indexes not strictly increasing")
    signatures.add signature
    indexes.add index
    prevIndex = index
    havePrev = true
  ChannelWithdrawOpProof(signatures: signatures, indexes: indexes)

func decodeChannelWithdrawOpProof*(data: openArray[byte]): ChannelWithdrawOpProof {.raises: [DecodingError].} =
  var pos = 0
  result = readChannelWithdrawOpProof(data, pos)
  finishDecode(data, pos)

proc readOpProof(data: openArray[byte], pos: var int, kind: OpProofKind): OpProof {.raises: [DecodingError].} =
  case kind
  of opfChannelInscribe:
    OpProof(kind: opfChannelInscribe, ed25519SigProof: readEd25519Signature(data, pos))
  of opfTransfer:
    OpProof(kind: opfTransfer, transferProof: readFixed[128](data, pos))
  of opfSdpWithdraw:
    OpProof(kind: opfSdpWithdraw, sdpWithdrawProof: readFixed[128](data, pos))
  of opfSdpActive:
    OpProof(kind: opfSdpActive, sdpActiveProof: readFixed[128](data, pos))
  of opfSdpDeclare:
    let zkSig = readFixed[128](data, pos)
    let ed25519Sig = readEd25519Signature(data, pos)
    OpProof(
      kind: opfSdpDeclare,
      declarationProof: ZkAndEd25519SigsProof(zkSig: zkSig, ed25519Sig: ed25519Sig),
    )
  of opfChannelWithdraw:
    OpProof(
      kind: opfChannelWithdraw,
      channelWithdrawOpProof: readChannelWithdrawOpProof(data, pos),
    )
  of opfLeaderClaim:
    OpProof(kind: opfLeaderClaim, proofOfClaimProof: readFixed[128](data, pos))
  of opfChannelConfig:
    OpProof(
      kind: opfChannelConfig,
      channelConfigOpProof: readChannelWithdrawOpProof(data, pos),
    )
  of opfChannelDeposit:
    OpProof(kind: opfChannelDeposit, channelDepositProof: readFixed[128](data, pos))

func decodeOpProof*(data: openArray[byte], kind: OpProofKind): OpProof {.raises: [DecodingError].} =
  var pos = 0
  result = readOpProof(data, pos, kind)
  finishDecode(data, pos)


proc readOpPayload(data: openArray[byte], pos: var int, opcode: Opcode): OpPayload {.raises: [DecodingError].} =
  case opcode
  of OpTransfer:
    let inputs = readInputs(data, pos)
    let outputs = readOutputs(data, pos)
    OpPayload(kind: Transfer, transfer: TransferPayload(inputs: inputs, outputs: outputs))
  of OpChannelInscribe:
    let channelId = readFixed[32](data, pos)
    let inscription = readU32LeLenPrefixed(data, pos)
    let parent = readFixed[32](data, pos)
    var signerKey: Ed25519PublicKey
    if not signerKey.init(readFixed[EdPublicKeySize](data, pos)):
      raise newException(DecodingError, "invalid Signer bytes")
    OpPayload(
      kind: ChannelInscribe,
      channelInscribe: ChannelInscribePayload(
        channelId: channelId,
        inscription: inscription,
        parent: parent,
        signer: signerKey,
      ),
    )
  of OpChannelDeposit:
    let channel = readFixed[32](data, pos)
    let count = readByte(data, pos)
    var inputs = newSeqOfCap[NoteId](count)
    for _ in 0 ..< int(count):
      inputs.add decodeFieldElementAt(data, pos)
    let metadata = readU32LeLenPrefixed(data, pos)
    OpPayload(
      kind: ChannelDeposit,
      channelDeposit: ChannelDepositPayload(channel: channel, inputs: inputs, metadata: metadata),
    )
  of OpChannelWithdraw:
    let channel = readFixed[32](data, pos)
    let outputs = readOutputs(data, pos)
    let opIdNonce = readLe[uint32](data, pos)
    OpPayload(
      kind: ChannelWithdraw,
      channelWithdraw: ChannelWithdrawPayload(
        channel: channel, outputs: outputs.notes, opIdNonce: opIdNonce,
      ),
    )
  of OpSdpDeclare:
    let serviceType = readServiceType(data, pos)
    let locatorCount = readByte(data, pos)
    if locatorCount > MaxSdpLocators:
      raise newException(DecodingError, "SDPDeclare LocatorCount exceeds max supported locators")
    var locators = newSeqOfCap[Locator](locatorCount)
    for _ in 0 ..< int(locatorCount):
      locators.add readLocator(data, pos)
    var providerKey: Ed25519PublicKey
    if not providerKey.init(readFixed[EdPublicKeySize](data, pos)):
      raise newException(DecodingError, "invalid ProviderId bytes")
    let zkId = decodeFieldElementAt(data, pos)
    let lockedNoteId = decodeFieldElementAt(data, pos)
    OpPayload(
      kind: SdpDeclare,
      sdpDeclare: SdpDeclarePayload(
        serviceType: serviceType,
        locators: locators,
        providerId: providerKey,
        zkId: zkId,
        lockedNoteId: lockedNoteId,
      ),
    )
  of OpSdpWithdraw:
    let declarationId = readFixed[32](data, pos)
    let nonce = readLe[uint64](data, pos)
    let lockedNoteId = decodeFieldElementAt(data, pos)
    OpPayload(
      kind: SdpWithdraw,
      sdpWithdraw: SdpWithdrawPayload(
        declarationId: declarationId, nonce: nonce, lockedNoteId: lockedNoteId,
      ),
    )
  of OpSdpActive:
    let declarationId = readFixed[32](data, pos)
    let nonce = readLe[uint64](data, pos)
    let metadata = readU32LeLenPrefixed(data, pos)
    OpPayload(
      kind: SdpActive,
      sdpActive: SdpActivePayload(
        declarationId: declarationId, nonce: nonce, metadata: metadata,
      ),
    )
  of OpLeaderClaim:
    let rewardsRoot = decodeFieldElementAt(data, pos)
    let voucherNullifier = decodeFieldElementAt(data, pos)
    let publicKey = decodeFieldElementAt(data, pos)
    OpPayload(
      kind: LeaderClaim,
      leaderClaim: LeaderClaimPayload(
        rewardsRoot: rewardsRoot,
        voucherNullifier: voucherNullifier,
        publicKey: publicKey,
      ),
    )
  of OpChannelConfig:
    OpPayload(kind: ChannelConfig, channelConfig: default(ChannelConfigPayload))
  else:
    raise newException(DecodingError, "unsupported opcode for OpPayload decode: " & $opcode)

proc readOp(data: openArray[byte], pos: var int): Op {.raises: [DecodingError].} =
  let opcode = Opcode(readByte(data, pos))
  let payload = readOpPayload(data, pos, opcode)
  Op(opcode: opcode, payload: payload)

func decodeOp*(data: openArray[byte]): Op {.raises: [DecodingError].} =
  var pos = 0
  result = readOp(data, pos)
  finishDecode(data, pos)

func decodeOps*(data: openArray[byte]): seq[Op] {.raises: [DecodingError].} =
  var pos = 0
  let count = readByte(data, pos)
  result = newSeqOfCap[Op](count)
  for _ in 0 ..< int(count):
    result.add readOp(data, pos)
  finishDecode(data, pos)

func decodeOpsProofs*(ops: openArray[Op], data: openArray[byte]): seq[OpProof] {.raises: [DecodingError].} =
  var pos = 0
  result = newSeqOfCap[OpProof](ops.len)
  var i = 0
  while pos < data.len:
    if i >= ops.len:
      raise newException(DecodingError, "OpsProofs length exceeds OpCount")
    let kind = expectedOpProofKindForOpcode(ops[i].opcode)
    result.add readOpProof(data, pos, kind)
    inc i
  if result.len > ops.len:
    raise newException(DecodingError, "OpsProofs length exceeds OpCount")
  finishDecode(data, pos)

func decodeOpPayload*(data: openArray[byte], opcode: Opcode): OpPayload {.raises: [DecodingError].} =
  var pos = 0
  result = readOpPayload(data, pos, opcode)
  finishDecode(data, pos)


func decodeMantleTx*(data: openArray[byte]): MantleTx {.raises: [DecodingError].} =
  var pos = 0
  let count = readByte(data, pos)
  var ops = newSeqOfCap[Op](count)
  for _ in 0 ..< int(count):
    ops.add readOp(data, pos)
  let executionGasPrice = TokenValue(readLe[uint64](data, pos))
  let permanentStorageGasPrice = TokenValue(readLe[uint64](data, pos))
  finishDecode(data, pos)
  MantleTx(
    ops: ops,
    executionGasPrice: executionGasPrice,
    permanentStorageGasPrice: permanentStorageGasPrice,
  )

func decodeSignedMantleTx*(data: openArray[byte]): SignedMantleTx {.raises: [DecodingError].} =
  var pos = 0
  let count = readByte(data, pos)
  var ops = newSeqOfCap[Op](count)
  for _ in 0 ..< int(count):
    ops.add readOp(data, pos)
  let executionGasPrice = TokenValue(readLe[uint64](data, pos))
  let permanentStorageGasPrice = TokenValue(readLe[uint64](data, pos))
  let tx = MantleTx(
    ops: ops,
    executionGasPrice: executionGasPrice,
    permanentStorageGasPrice: permanentStorageGasPrice,
  )
  var proofs = newSeqOfCap[OpProof](ops.len)
  var i = 0
  while pos < data.len:
    if i >= ops.len:
      raise newException(DecodingError, "OpsProofs length exceeds OpCount")
    let kind = expectedOpProofKindForOpcode(ops[i].opcode)
    proofs.add readOpProof(data, pos, kind)
    inc i
  if proofs.len > ops.len:
    raise newException(DecodingError, "OpsProofs length exceeds OpCount")
  finishDecode(data, pos)
  SignedMantleTx(tx: tx, opProofs: proofs)

{.pop.}
