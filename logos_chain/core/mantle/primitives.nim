# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [Bedrock v1.1 — Mantle Specification v1.10.0](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md)

{.push raises: [], gcsafe.}

import
  results,
  ../crypto/[hashing, types],
  libp2p/multiaddress,
  poseidon2/[types, io]
export hashing, types, io
export
  encodeByte, encodeEd25519PublicKey, encodeEd25519Signature, encodeFieldElement,
  encodeGroth16, encodeHash32, encodeU16LeLenPrefixed, encodeU32LeLenPrefixed,
  encodeLe, encodeZkPublicKey, encodeZkSignature,
  decodeByte, decodeEd25519PublicKey, decodeEd25519Signature, decodeFieldElement,
  decodeFieldElementAt, decodeGroth16, decodeHash32, decodeU16LeLenPrefixed,
  decodeU32LeLenPrefixed, decodeZkPublicKey, decodeZkSignature

const
  MaxBlockTxs* = 1024
  MantleMaxOps* = 255
  MaxSdpLocators* = 8
  MaxLocatorMultiaddrBytes* = 329


type
  MessageId* = Hash32
  ChannelId* = Hash32
  DeclarationId* = Hash32
  Parent* = Hash32
  References* = array[MaxBlockTxs, Hash32]

  Inscription* = seq[byte]
  Metadata* = seq[byte]

  SlotNumber* = uint64
  BlockNumber* = uint64
  EpochNumber* = uint32
  NumberOfEpochs* = uint32
  RewardVoucher* = array[32, byte]

  TokenValue* = uint64
  Value* = uint64
  Amount* = uint64
  Nonce* = uint64

  PostingTimeframe* = uint32
  PostingTimeout* = uint32

  ConfigurationThreshold* = uint16
  TransferThreshold* = uint16

  ServiceType* {.pure.} = enum
    bn = "BN"
  Locator* = MultiAddress

  Opcode* = uint8
  OpCount* = uint8
  HexBytes* = string

  NoteId* = FieldElement
  Note* = object
    value*: Value
    zkPublicKey*: ZkPublicKey
  Inputs* = object
    noteIds*: seq[NoteId]
  Outputs* = object
    notes*: seq[Note]
  PublicKey* = ZkPublicKey
  RewardsRoot* = FieldElement
  VoucherNullifier* = FieldElement

  ProviderId* = Ed25519PublicKey
  ZkId* = ZkPublicKey
  LockedNoteId* = NoteId
  Signer* = Ed25519PublicKey

  SignatureCount* = uint16
  ChannelKeyIndex* = uint16
  KeyCount* = uint16

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

func encodeOpcode*(value: Opcode): byte =
  ## Opcode = Byte
  encodeByte(byte(value))

func encodeOpCount*(value: OpCount): byte =
  ## OpCount = Byte
  encodeByte(byte(value))

func encodeValue*(value: Value): array[8, byte] =
  ## Value = UINT64
  encodeLe(value)

func encodeAmount*(value: Amount): array[8, byte] =
  ## Amount = UINT64
  encodeLe(value)

func encodeNonce*(value: Nonce): array[8, byte] =
  ## Nonce = UINT64
  encodeLe(value)

func encodeMetadata*(value: Metadata): seq[byte] =
  ## Metadata = UINT32 * BYTE
  ## Service-specific node activeness metadata.
  doAssert value.len <= int(high(uint32)),
    "Metadata length exceeds UINT32 range"
  var res = @(encodeLe(uint32(value.len)))
  res.add(value)
  res

func encodeSignatureCount*(value: SignatureCount): array[2, byte] =
  ## SignatureCount = UINT16
  encodeLe(uint16(value))

func encodeChannelKeyIndex*(value: ChannelKeyIndex): array[2, byte] =
  ## ChannelKeyIndex = UINT16
  encodeLe(uint16(value))

func encodeKeyCount*(value: KeyCount): array[2, byte] =
  ## KeyCount = UINT16
  encodeLe(uint16(value))

func encodePostingTimeframe*(value: PostingTimeframe): array[4, byte] =
  ## PostingTimeframe = UINT32
  encodeLe(value)

func encodePostingTimeout*(value: PostingTimeout): array[4, byte] =
  ## PostingTimeout = UINT32
  encodeLe(value)

func encodeConfigurationThreshold*(value: ConfigurationThreshold): array[2, byte] =
  ## ConfigThreshold = UINT16
  encodeLe(value)

func encodeTransferThreshold*(value: TransferThreshold): array[2, byte] =
  ## TransferThreshold = UINT16
  encodeLe(value)


func encodeNote*(value: Note): array[40, byte] =
  ## Note = Value || ZkPublicKey
  var res: array[40, byte]
  res[0 ..< 8] = encodeValue(value.value)
  res[8 ..< 40] = encodeZkPublicKey(value.zkPublicKey)
  res

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
  var res: seq[byte]
  res.add(encodeInputCount(byte(value.noteIds.len)))
  for noteId in value.noteIds:
    res.add(encodeNoteId(noteId))
  res

func encodeInputs*(value: openArray[NoteId]): seq[byte] =
  ## Inputs = InputCount * NoteId
  doAssert value.len <= int(high(byte)),
    "Inputs: InputCount exceeds Byte range"
  var res: seq[byte]
  res.add(encodeInputCount(byte(value.len)))
  for noteId in value:
    res.add(encodeNoteId(noteId))
  res

func encodeOutputs*(value: Outputs): seq[byte] =
  ## Outputs = OutputCount * Note
  doAssert value.notes.len <= int(high(byte)),
    "Outputs: OutputCount exceeds Byte range"
  var res: seq[byte]
  res.add(encodeOutputCount(byte(value.notes.len)))
  for note in value.notes:
    res.add(encodeNote(note))
  res

func encodeInscription*(value: Inscription): seq[byte] =
  ## Inscription = UINT32 * BYTE
  encodeU32LeLenPrefixed(value)

func encodeServiceType*(value: ServiceType): byte =
  ## Wire ``ServiceType`` = single byte (``ord``). Used by ``encodeSdpDeclare`` /
  ## ``encode_mantle_tx`` and ``declaration_id``.
  encodeByte(byte(ord(value)))

func isValidLocator*(locator: Locator): bool =
  locator.data().buffer.len <= MaxLocatorMultiaddrBytes

func encodeLocatorCount*(value: byte): byte =
  ## LocatorCount = Byte
  encodeByte(value)

func encodeLocator*(value: Locator): seq[byte] =
  ## Locator = 2Byte * BYTE ; Max 329 bytes, multiaddr format
  let locatorBytes = value.data().buffer
  doAssert locatorBytes.len <= MaxLocatorMultiaddrBytes,
    "Locator exceeds max multiaddr byte length"
  encodeU16LeLenPrefixed(locatorBytes)

func byteLen*(locator: Locator): int =
  ## Exact wire byte length of a Locator: 2-byte prefix + multiaddr bytes.
  sizeof(uint16) + locator.data().buffer.len

func encodeLocators*(locators: openArray[Locator]): seq[byte] =
  ## Locators = LocatorCount *Locator
  var res = @[encodeLocatorCount(byte(locators.len))]
  for locator in locators:
    res.add(encodeLocator(locator))
  res

func slotToFr*(slot: SlotNumber): FieldElement =
  ## Convert a ``SlotNumber`` to a BN254 field element via 8-byte
  ## little-endian zero-padded encoding.
  frFromBytesLE(encodeLe(uint64(slot))).get

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

func decodeOpcode*(data: openArray[byte]): Opcode {.raises: [DecodingError].} =
  Opcode(decodeByte(data))

func decodeOpCount*(data: openArray[byte]): OpCount {.raises: [DecodingError].} =
  OpCount(decodeByte(data))

func decodeValue*(data: openArray[byte]): Value {.raises: [DecodingError].} =
  var pos = 0
  let res = readLe[uint64](data, pos)
  finishDecode(data, pos)
  res

func decodeAmount*(data: openArray[byte]): Amount {.raises: [DecodingError].} =
  decodeValue(data)

func decodeNonce*(data: openArray[byte]): Nonce {.raises: [DecodingError].} =
  decodeValue(data)

func decodeMetadata*(data: openArray[byte]): Metadata {.raises: [DecodingError].} =
  decodeU32LeLenPrefixed(data)

func decodeInscription*(data: openArray[byte]): Inscription {.raises: [DecodingError].} =
  decodeU32LeLenPrefixed(data)

func readServiceType*(data: openArray[byte], pos: var int): ServiceType {.raises: [DecodingError].} =
  let b = readByte(data, pos)
  case b
  of byte(ord(ServiceType.bn)):
    ServiceType.bn
  else:
    raise newException(DecodingError, "invalid ServiceType byte: " & $b)

func decodeServiceType*(data: openArray[byte]): ServiceType {.raises: [DecodingError].} =
  var pos = 0
  let res = readServiceType(data, pos)
  finishDecode(data, pos)
  res

func decodeLocatorCount*(data: openArray[byte]): byte {.raises: [DecodingError].} =
  decodeByte(data)

func readLocator*(data: openArray[byte], pos: var int): Locator {.raises: [DecodingError].} =
  let raw = readU16LeLenPrefixed(data, pos)
  if raw.len > MaxLocatorMultiaddrBytes:
    raise newException(DecodingError, "Locator exceeds max multiaddr byte length")
  MultiAddress.init(raw).valueOr:
    raise newException(DecodingError, "invalid Locator multiaddr: " & error)

func decodeLocator*(data: openArray[byte]): Locator {.raises: [DecodingError].} =
  var pos = 0
  let res = readLocator(data, pos)
  finishDecode(data, pos)
  res

func decodeSignatureCount*(data: openArray[byte]): SignatureCount {.raises: [DecodingError].} =
  var pos = 0
  let res = SignatureCount(readLe[uint16](data, pos))
  finishDecode(data, pos)
  res

func decodeChannelKeyIndex*(data: openArray[byte]): ChannelKeyIndex {.raises: [DecodingError].} =
  var pos = 0
  let res = ChannelKeyIndex(readLe[uint16](data, pos))
  finishDecode(data, pos)
  res

func decodeKeyCount*(data: openArray[byte]): KeyCount {.raises: [DecodingError].} =
  var pos = 0
  let res = KeyCount(readLe[uint16](data, pos))
  finishDecode(data, pos)
  res


func readNote*(data: openArray[byte], pos: var int): Note {.raises: [DecodingError].} =
  let value = Value(readLe[uint64](data, pos))
  let zkPublicKey = decodeFieldElementAt(data, pos)
  Note(value: value, zkPublicKey: zkPublicKey)

func readInputs*(data: openArray[byte], pos: var int): Inputs {.raises: [DecodingError].} =
  let count = readByte(data, pos)
  var noteIds = newSeqOfCap[NoteId](count)
  for _ in 0 ..< int(count):
    noteIds.add decodeFieldElementAt(data, pos)
  Inputs(noteIds: noteIds)

func readOutputs*(data: openArray[byte], pos: var int): Outputs {.raises: [DecodingError].} =
  let count = readByte(data, pos)
  var notes = newSeqOfCap[Note](count)
  for _ in 0 ..< int(count):
    notes.add readNote(data, pos)
  Outputs(notes: notes)

func decodeNote*(data: openArray[byte]): Note {.raises: [DecodingError].} =
  var pos = 0
  let res = readNote(data, pos)
  finishDecode(data, pos)
  res

func decodeInputCount*(data: openArray[byte]): byte {.raises: [DecodingError].} =
  decodeByte(data)

func decodeOutputCount*(data: openArray[byte]): byte {.raises: [DecodingError].} =
  decodeByte(data)

func decodeInputs*(data: openArray[byte]): Inputs {.raises: [DecodingError].} =
  var pos = 0
  let res = readInputs(data, pos)
  finishDecode(data, pos)
  res

func decodeInputsNoteIds*(data: openArray[byte]): seq[NoteId] {.raises: [DecodingError].} =
  decodeInputs(data).noteIds

func decodeOutputs*(data: openArray[byte]): Outputs {.raises: [DecodingError].} =
  var pos = 0
  let res = readOutputs(data, pos)
  finishDecode(data, pos)
  res

{.pop.}
