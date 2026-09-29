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
  encodeGroth16, encodeHash32, encodeU32LeLenPrefixed,
  encodeLe, encodeZkPublicKey, encodeZkSignature,
  decodeFieldElement, decodeFieldElementAt, decodeU32LeLenPrefixed

const
  MaxBlockTxs* = 1024
  MantleMaxOps* = 255
  MaxInputs* = 255
  MaxOutputs* = 255
  MaxSdpLocators* = 8
  MaxLocatorMultiaddrBytes* = 329

type
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

const NoteWireBytes = sizeof(Value) + sizeof(ZkPublicKey)

func byteLen*(inputs: Inputs): int =
  ## Exact wire byte length of Inputs: 1-byte InputCount + NoteIds
  sizeof(byte) + inputs.noteIds.len * sizeof(NoteId)

func byteLen*(outputs: Outputs): int =
  ## Exact wire byte length of Outputs: 1-byte OutputCount + Notes
  sizeof(byte) + outputs.notes.len * NoteWireBytes

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

func encodeNoteId(value: NoteId): array[32, byte] =
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

func encodeNonce*(value: Nonce): array[8, byte] =
  ## Nonce = UINT64
  encodeLe(value)

func encodeMetadata*(value: Metadata): Result[seq[byte], EncodingError] =
  ## Metadata = UINT32 * BYTE
  ## Service-specific node activeness metadata.
  let enc = encodeU32LeLenPrefixed(value).valueOr:
    return err(EncodingError.MetadataLengthExceeded)
  ok(enc)

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

func encodeNote(value: Note): array[NoteWireBytes, byte] =
  ## Note = Value || ZkPublicKey
  var res: array[NoteWireBytes, byte]
  res[0 ..< sizeof(Value)] = encodeValue(value.value)
  res[sizeof(Value) ..< NoteWireBytes] = encodeZkPublicKey(value.zkPublicKey)
  res

func encodeInputCount(value: byte): byte =
  ## InputCount = Byte
  encodeByte(value)

func encodeOutputCount(value: byte): byte =
  ## OutputCount = Byte
  encodeByte(value)

func encodeInputs*(value: Inputs): Result[seq[byte], EncodingError] =
  ## Inputs = InputCount * NoteId
  if value.noteIds.len > MaxInputs:
    return err(EncodingError.InputsCountExceeded)
  var res = newSeqOfCap[byte](byteLen(value))
  res.add(encodeInputCount(byte(value.noteIds.len)))
  for noteId in value.noteIds:
    res.add(encodeNoteId(noteId))
  ok(res)

func encodeOutputs*(value: Outputs): Result[seq[byte], EncodingError] =
  ## Outputs = OutputCount * Note
  if value.notes.len > MaxOutputs:
    return err(EncodingError.OutputsCountExceeded)
  var res = newSeqOfCap[byte](byteLen(value))
  res.add(encodeOutputCount(byte(value.notes.len)))
  for note in value.notes:
    res.add(encodeNote(note))
  ok(res)

func encodeInscription*(value: Inscription): Result[seq[byte], EncodingError] =
  ## Inscription = UINT32 * BYTE
  let enc = encodeU32LeLenPrefixed(value).valueOr:
    return err(EncodingError.InscriptionLengthExceeded)
  ok(enc)

func encodeServiceType*(value: ServiceType): byte =
  ## Wire ``ServiceType`` = single byte (``ord``). Used by ``encodeSdpDeclare`` /
  ## ``encode_mantle_tx`` and ``declaration_id``.
  encodeByte(byte(ord(value)))

func isValidLocator*(locator: Locator): bool =
  locator.data().buffer.len <= MaxLocatorMultiaddrBytes

func encodeLocatorCount(value: byte): byte =
  ## LocatorCount = Byte
  encodeByte(value)

func encodeLocator*(value: Locator): Result[seq[byte], EncodingError] =
  ## Locator = 2Byte * BYTE ; Max 329 bytes, multiaddr format
  let locatorBytes = value.data().buffer
  if locatorBytes.len > MaxLocatorMultiaddrBytes:
    return err(EncodingError.LocatorLengthExceeded)
  var enc = @(encodeLe(uint16(locatorBytes.len)))
  enc.add(locatorBytes)
  ok(enc)

func byteLen*(locator: Locator): int =
  ## Exact wire byte length of a Locator: 2-byte prefix + multiaddr bytes.
  sizeof(uint16) + locator.data().buffer.len

func encodeLocators*(locators: openArray[Locator]): Result[seq[byte], EncodingError] =
  ## Locators = LocatorCount *Locator
  if locators.len > MaxSdpLocators:
    return err(EncodingError.LocatorsCountExceeded)
  var res = @[encodeLocatorCount(byte(locators.len))]
  for locator in locators:
    let enc = ?encodeLocator(locator)
    res.add(enc)
  ok(res)

func slotToFr*(slot: SlotNumber): FieldElement =
  ## Convert a ``SlotNumber`` to a BN254 field element via 8-byte
  ## little-endian zero-padded encoding.
  frFromBytesLE(encodeLe(uint64(slot))).get

func readServiceType*(data: openArray[byte], pos: var int): Result[ServiceType, DecodingError] =
  let b = ?readByte(data, pos)
  case b
  of byte(ord(ServiceType.bn)):
    ok(ServiceType.bn)
  else:
    err(DecodingError.InvalidServiceType)

func readLocator*(data: openArray[byte], pos: var int): Result[Locator, DecodingError] =
  let raw = ?readU16LeLenPrefixed(data, pos)
  if raw.len > MaxLocatorMultiaddrBytes:
    return err(DecodingError.LocatorLengthExceeded)
  let ma = MultiAddress.init(raw).valueOr:
    return err(DecodingError.InvalidLocator)
  ok(ma)

func readNote(data: openArray[byte], pos: var int): Result[Note, DecodingError] =
  let value = Value(?readLe[uint64](data, pos))
  let zkPublicKey = ?decodeFieldElementAt(data, pos)
  ok(Note(value: value, zkPublicKey: zkPublicKey))

func readInputs*(data: openArray[byte], pos: var int): Result[Inputs, DecodingError] =
  let count = ?readByte(data, pos)
  var noteIds = newSeqOfCap[NoteId](count)
  for _ in 0 ..< int(count):
    noteIds.add ?decodeFieldElementAt(data, pos)
  ok(Inputs(noteIds: noteIds))

func readOutputs*(data: openArray[byte], pos: var int): Result[Outputs, DecodingError] =
  let count = ?readByte(data, pos)
  var notes = newSeqOfCap[Note](count)
  for _ in 0 ..< int(count):
    notes.add ?readNote(data, pos)
  ok(Outputs(notes: notes))

{.pop.}
