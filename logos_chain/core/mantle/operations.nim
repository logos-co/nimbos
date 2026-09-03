# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [Bedrock v1.1 — Mantle Specification v1.10.0](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md)

{.push raises: [], gcsafe.}

import
  ./[primitives, opcodes],
  ../crypto/types,
  libp2p/crypto/ed25519/ed25519
export primitives, opcodes


type
  TransferPayload* = object
    inputs*: Inputs
    outputs*: Outputs


type
  ChannelInscribePayload* = object
    channelId*: ChannelId
    inscription*: Inscription
    parent*: Parent
    signer*: Signer

type
  ChannelDepositPayload* = object
    channel*: ChannelId
    inputs*: seq[NoteId]
    metadata*: Metadata


type
  ChannelWithdrawPayload* = object
    channel*: ChannelId
    inputs*: seq[NoteId]

type
  ChannelTransferPayload* = object
    channel*: ChannelId
    inputs*: seq[NoteId]
    outputs*: seq[Note]


type
  DeclarationMessage* = object
    serviceType*: ServiceType
    locators*: seq[Locator]
    providerId*: ProviderId
    lockedNoteId*: NoteId
    zkId*: ZkId

  WithdrawMessage* = object
    declarationId*: DeclarationId
    lockedNoteId*: NoteId
    nonce*: Nonce

  ActiveMessage* = object
    declarationId*: DeclarationId
    nonce*: Nonce
    metadata*: Metadata

type
  LeaderClaimPayload* = object
    rewardsRoot*: RewardsRoot
    voucherNullifier*: VoucherNullifier
    publicKey*: PublicKey

type
  ChannelConfigPayload* = object
    channel*: ChannelId
    keys*: seq[Ed25519PublicKey]
    postingTimeframe*: PostingTimeframe
    postingTimeout*: PostingTimeout
    configurationThreshold*: ConfigurationThreshold
    transferThreshold*: TransferThreshold


type
  OpPayloadTag* {.pure.} = enum
    Transfer
    ChannelInscribe
    ChannelDeposit
    ChannelWithdraw
    ChannelTransfer
    SdpDeclare
    SdpWithdraw
    SdpActive
    LeaderClaim
    ChannelConfig

  OpPayload* = object
    case kind*: OpPayloadTag
    of Transfer: transfer*: TransferPayload
    of ChannelInscribe: channelInscribe*: ChannelInscribePayload
    of ChannelDeposit: channelDeposit*: ChannelDepositPayload
    of ChannelWithdraw: channelWithdraw*: ChannelWithdrawPayload
    of ChannelTransfer: channelTransfer*: ChannelTransferPayload
    of SdpDeclare: sdpDeclare*: DeclarationMessage
    of SdpWithdraw: sdpWithdraw*: WithdrawMessage
    of SdpActive: sdpActive*: ActiveMessage
    of LeaderClaim: leaderClaim*: LeaderClaimPayload
    of ChannelConfig: channelConfig*: ChannelConfigPayload

  Op* = object
    opcode*: Opcode
    payload*: OpPayload


func createTransferOp*(payload: TransferPayload): Op =
  Op(opcode: OpTransfer, payload: OpPayload(kind: Transfer, transfer: payload))

func createChannelInscribeOp*(payload: ChannelInscribePayload): Op =
  Op(
    opcode: OpChannelInscribe,
    payload: OpPayload(kind: ChannelInscribe, channelInscribe: payload),
  )

func createChannelDepositOp*(payload: ChannelDepositPayload): Op =
  Op(
    opcode: OpChannelDeposit,
    payload: OpPayload(kind: ChannelDeposit, channelDeposit: payload),
  )

func createChannelWithdrawOp*(payload: ChannelWithdrawPayload): Op =
  Op(
    opcode: OpChannelWithdraw,
    payload: OpPayload(kind: ChannelWithdraw, channelWithdraw: payload),
  )

func createChannelTransferOp*(payload: ChannelTransferPayload): Op =
  Op(
    opcode: OpChannelTransfer,
    payload: OpPayload(kind: ChannelTransfer, channelTransfer: payload),
  )

func createSdpDeclareOp*(payload: DeclarationMessage): Op =
  Op(opcode: OpSdpDeclare, payload: OpPayload(kind: SdpDeclare, sdpDeclare: payload))

func createSdpWithdrawOp*(payload: WithdrawMessage): Op =
  Op(
    opcode: OpSdpWithdraw,
    payload: OpPayload(kind: SdpWithdraw, sdpWithdraw: payload),
  )

func createSdpActiveOp*(payload: ActiveMessage): Op =
  Op(opcode: OpSdpActive, payload: OpPayload(kind: SdpActive, sdpActive: payload))

func createLeaderClaimOp*(payload: LeaderClaimPayload): Op =
  Op(opcode: OpLeaderClaim, payload: OpPayload(kind: LeaderClaim, leaderClaim: payload))

func createChannelConfigOp*(payload: ChannelConfigPayload): Op =
  Op(
    opcode: OpChannelConfig,
    payload: OpPayload(kind: ChannelConfig, channelConfig: payload),
  )


func opPayloadToOpcode*(p: OpPayload): Opcode =
  case p.kind
  of Transfer: OpTransfer
  of ChannelInscribe: OpChannelInscribe
  of ChannelDeposit: OpChannelDeposit
  of ChannelWithdraw: OpChannelWithdraw
  of ChannelTransfer: OpChannelTransfer
  of SdpDeclare: OpSdpDeclare
  of SdpWithdraw: OpSdpWithdraw
  of SdpActive: OpSdpActive
  of LeaderClaim: OpLeaderClaim
  of ChannelConfig: OpChannelConfig

func isSupportedOpcode*(opcode: Opcode): bool =
  ## True when opcode is part of the currently supported Mantle operation set.
  case opcode
  of OpTransfer, OpChannelInscribe, OpChannelDeposit, OpChannelWithdraw,
     OpChannelTransfer, OpSdpDeclare, OpSdpWithdraw, OpSdpActive, OpLeaderClaim,
     OpChannelConfig:
    true
  else:
    false

func defaultOpForOpcode*(opcode: Opcode): Op =
  ## Canonical default/empty op payload for a given opcode.
  case opcode
  of OpTransfer:
    createTransferOp(TransferPayload(
      inputs: Inputs(noteIds: @[]),
      outputs: Outputs(notes: @[]),
    ))
  of OpChannelInscribe:
    createChannelInscribeOp(ChannelInscribePayload(
      channelId: default(ChannelId),
      inscription: @[],
      parent: default(Parent),
      signer: default(Signer),
    ))
  of OpChannelDeposit:
    createChannelDepositOp(ChannelDepositPayload(
      channel: default(ChannelId),
      inputs: @[],
      metadata: @[],
    ))
  of OpChannelWithdraw:
    createChannelWithdrawOp(ChannelWithdrawPayload(
      channel: default(ChannelId),
      inputs: @[],
    ))
  of OpChannelTransfer:
    createChannelTransferOp(ChannelTransferPayload(
      channel: default(ChannelId),
      inputs: @[],
      outputs: @[],
    ))
  of OpSdpDeclare:
    createSdpDeclareOp(DeclarationMessage(
      serviceType: default(ServiceType),
      locators: @[],
      providerId: default(ProviderId),
      zkId: default(ZkId),
      lockedNoteId: default(LockedNoteId),
    ))
  of OpSdpWithdraw:
    createSdpWithdrawOp(WithdrawMessage(
      declarationId: default(DeclarationId),
      nonce: default(Nonce),
      lockedNoteId: default(LockedNoteId),
    ))
  of OpSdpActive:
    createSdpActiveOp(ActiveMessage(
      declarationId: default(DeclarationId),
      nonce: default(Nonce),
      metadata: @[],
    ))
  of OpLeaderClaim:
    createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(ZkPublicKey),
    ))
  of OpChannelConfig:
    createChannelConfigOp(ChannelConfigPayload(
      channel: default(ChannelId),
      keys: @[],
      postingTimeframe: default(PostingTimeframe),
      postingTimeout: default(PostingTimeout),
      configurationThreshold: default(ConfigurationThreshold),
      transferThreshold: default(TransferThreshold),
    ))
  else:
    doAssert false, "unknown opcode for default op: " & $opcode
    default(Op)

func encodeTransfer*(value: TransferPayload): seq[byte] =
  ## Transfer = Inputs || Outputs
  var res = encodeInputs(value.inputs)
  res.add(encodeOutputs(value.outputs))
  res

func encodeSdpDeclare*(value: DeclarationMessage): seq[byte] =
  ## SDPDeclare = ServiceType LocatorCount *Locator ProviderId ZkId LockedNoteId
  var res = @[encodeServiceType(value.serviceType)]
  res.add(encodeLocators(value.locators))
  res.add(encodeProviderId(value.providerId))
  res.add(encodeZkId(value.zkId))
  res.add(encodeLockedNoteId(value.lockedNoteId))
  res

func declarationId*(declaration: DeclarationMessage): DeclarationId =
  ## ``declaration_id``: wire ServiceType byte, ProviderId 32B, ZkId 32B,
  ## then wire locators (u8 count + u16-prefixed multiaddr bytes), blake2b256.
  var preimage = @[encodeServiceType(declaration.serviceType)]
  preimage.add(encodeProviderId(declaration.providerId))
  preimage.add(encodeZkId(declaration.zkId))
  preimage.add(encodeLocators(declaration.locators))
  blake2b256Hash(preimage)

func encodeSdpWithdraw*(value: WithdrawMessage): array[72, byte] =
  ## SDPWithdraw = DeclarationId || Nonce || LockedNoteId
  var res: array[72, byte]
  res[0 ..< 32] = encodeDeclarationId(value.declarationId)
  res[32 ..< 40] = encodeNonce(value.nonce)
  res[40 ..< 72] = encodeLockedNoteId(value.lockedNoteId)
  res

func encodeSdpActive*(value: ActiveMessage): seq[byte] =
  ## SDPActive = DeclarationId || Nonce || Metadata
  var res = @(encodeDeclarationId(value.declarationId))
  res.add(encodeNonce(value.nonce))
  res.add(encodeMetadata(value.metadata))
  res

func encodeLeaderClaim*(value: LeaderClaimPayload): array[96, byte] =
  ## LeaderClaim = RewardsRoot || VoucherNullifier || PublicKey
  var res: array[96, byte]
  res[0 ..< 32] = encodeRewardsRoot(value.rewardsRoot)
  res[32 ..< 64] = encodeVoucherNullifier(value.voucherNullifier)
  res[64 ..< 96] = encodePublicKey(value.publicKey)
  res

func encodeChannelWithdraw*(value: ChannelWithdrawPayload): seq[byte] =
  ## ChannelWithdraw = ChannelId || Inputs
  var res = @(encodeChannelId(value.channel))
  res.add(encodeInputs(value.inputs))
  res

func encodeChannelTransfer*(value: ChannelTransferPayload): seq[byte] =
  ## ChannelTransfer = ChannelId || Inputs || Outputs
  var res = @(encodeChannelId(value.channel))
  res.add(encodeInputs(value.inputs))
  res.add(encodeOutputs(Outputs(notes: value.outputs)))
  res

func encodeChannelDeposit*(value: ChannelDepositPayload): seq[byte] =
  ## ChannelDeposit = ChannelId || Inputs || Metadata
  var res = @(encodeChannelId(value.channel))
  res.add(encodeInputs(value.inputs))
  res.add(encodeMetadata(value.metadata))
  res

func encodeChannelConfig*(value: ChannelConfigPayload): seq[byte] =
  ## ChannelConfig = ChannelId || KeyCount || *Signer || PostingTimeframe ||
  ##                 PostingTimeout || ConfigThreshold || TransferThreshold
  doAssert value.keys.len <= int(high(uint16)),
    "ChannelConfig: KeyCount exceeds UINT16 range"
  var res = @(encodeChannelId(value.channel))
  res.add(encodeKeyCount(KeyCount(value.keys.len)))
  for key in value.keys:
    res.add(encodeSigner(key))
  res.add(encodePostingTimeframe(value.postingTimeframe))
  res.add(encodePostingTimeout(value.postingTimeout))
  res.add(encodeConfigurationThreshold(value.configurationThreshold))
  res.add(encodeTransferThreshold(value.transferThreshold))
  res

func encodeChannelInscribe*(value: ChannelInscribePayload): seq[byte] =
  ## ChannelInscribe = ChannelId || Inscription || Parent || Signer
  var res = @(encodeChannelId(value.channelId))
  res.add(encodeInscription(value.inscription))
  res.add(encodeParent(value.parent))
  res.add(encodeSigner(value.signer))
  res

func encodeOpPayload*(payload: OpPayload): seq[byte] =
  ## OpPayload = Transfer /
  ##             ChannelInscribe /
  ##             ChannelDeposit /
  ##             ChannelWithdraw /
  ##             ChannelTransfer /
  ##             SDPDeclare /
  ##             SDPWithdraw /
  ##             SDPActive /
  ##             LeaderClaim /
  ##             ChannelConfig
  case payload.kind
  of Transfer:
    encodeTransfer(payload.transfer)
  of ChannelInscribe:
    encodeChannelInscribe(payload.channelInscribe)
  of ChannelDeposit:
    encodeChannelDeposit(payload.channelDeposit)
  of ChannelWithdraw:
    encodeChannelWithdraw(payload.channelWithdraw)
  of ChannelTransfer:
    encodeChannelTransfer(payload.channelTransfer)
  of SdpDeclare:
    encodeSdpDeclare(payload.sdpDeclare)
  of SdpWithdraw:
    @(encodeSdpWithdraw(payload.sdpWithdraw))
  of SdpActive:
    encodeSdpActive(payload.sdpActive)
  of LeaderClaim:
    @(encodeLeaderClaim(payload.leaderClaim))
  of ChannelConfig:
    encodeChannelConfig(payload.channelConfig)

func encodeOp*(op: Op): seq[byte] =
  ## Op = Opcode || OpPayload
  var res = @[encodeOpcode(op.opcode)]
  res.add(encodeOpPayload(op.payload))
  res

func encodeOps*(ops: openArray[Op]): seq[byte] =
  ## Ops = OpCount * Op
  doAssert ops.len <= int(high(uint8)),
    "Ops length exceeds OpCount byte range"
  var res = @[encodeOpCount(OpCount(uint8(ops.len)))]
  for op in ops:
    res.add(encodeOp(op))
  res

func byteLen*(payload: OpPayload): int =
  ## Exact wire byte length of an OpPayload without allocating buffers.
  case payload.kind
  of Transfer:
    template t: untyped = payload.transfer
    sizeof(byte) + t.inputs.noteIds.len * sizeof(NoteId) +
      sizeof(byte) + t.outputs.notes.len * (sizeof(Value) + sizeof(ZkPublicKey))
  of ChannelInscribe:
    template ci: untyped = payload.channelInscribe
    sizeof(ChannelId) + sizeof(uint32) + ci.inscription.len +
      sizeof(Parent) + sizeof(Signer)
  of ChannelDeposit:
    template cd: untyped = payload.channelDeposit
    sizeof(ChannelId) + sizeof(byte) + cd.inputs.len * sizeof(NoteId) +
      sizeof(uint32) + cd.metadata.len
  of ChannelWithdraw:
    template cw: untyped = payload.channelWithdraw
    sizeof(ChannelId) + sizeof(byte) + cw.inputs.len * sizeof(NoteId)
  of ChannelTransfer:
    template ct: untyped = payload.channelTransfer
    sizeof(ChannelId) + sizeof(byte) + ct.inputs.len * sizeof(NoteId) +
      sizeof(byte) + ct.outputs.len * (sizeof(Value) + sizeof(ZkPublicKey))
  of ChannelConfig:
    template cfg: untyped = payload.channelConfig
    sizeof(ChannelId) + sizeof(KeyCount) + cfg.keys.len * sizeof(Ed25519PublicKey) +
      sizeof(PostingTimeframe) + sizeof(PostingTimeout) +
      sizeof(ConfigurationThreshold) + sizeof(TransferThreshold)
  of SdpDeclare:
    template decl: untyped = payload.sdpDeclare
    var locLen = 0
    for loc in decl.locators:
      locLen += byteLen(loc)
    sizeof(byte) + sizeof(byte) + locLen + sizeof(ProviderId) +
      sizeof(ZkId) + sizeof(LockedNoteId)
  of SdpWithdraw:
    sizeof(DeclarationId) + sizeof(Nonce) + sizeof(LockedNoteId)
  of SdpActive:
    template act: untyped = payload.sdpActive
    sizeof(DeclarationId) + sizeof(Nonce) + sizeof(uint32) + act.metadata.len
  of LeaderClaim:
    sizeof(RewardsRoot) + sizeof(VoucherNullifier) + sizeof(ZkPublicKey)

func byteLen*(op: Op): int =
  ## Exact wire byte length of an Op: Opcode (1B) || OpPayload.
  sizeof(Opcode) + byteLen(op.payload)

func byteLen*(ops: openArray[Op]): int =
  ## Exact wire byte length of an Ops sequence: OpCount (1B) || *Op.
  var total = sizeof(OpCount)
  for op in ops:
    total += byteLen(op)
  total

func decodeTransfer*(data: openArray[byte]): TransferPayload {.raises: [DecodingError].} =
  var pos = 0
  let inputs = readInputs(data, pos)
  let outputs = readOutputs(data, pos)
  finishDecode(data, pos)
  TransferPayload(inputs: inputs, outputs: outputs)

func decodeSdpDeclare*(data: openArray[byte]): DeclarationMessage {.raises: [DecodingError].} =
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
  DeclarationMessage(
    serviceType: serviceType,
    locators: locators,
    providerId: providerKey,
    zkId: zkId,
    lockedNoteId: lockedNoteId,
  )

func decodeSdpWithdraw*(data: openArray[byte]): WithdrawMessage {.raises: [DecodingError].} =
  var pos = 0
  let declarationId = readFixed[32](data, pos)
  let nonce = readLe[uint64](data, pos)
  let lockedNoteId = decodeFieldElementAt(data, pos)
  finishDecode(data, pos)
  WithdrawMessage(
    declarationId: declarationId,
    nonce: nonce,
    lockedNoteId: lockedNoteId,
  )

func decodeSdpActive*(data: openArray[byte]): ActiveMessage {.raises: [DecodingError].} =
  var pos = 0
  let declarationId = readFixed[32](data, pos)
  let nonce = readLe[uint64](data, pos)
  let metadata = readU32LeLenPrefixed(data, pos)
  finishDecode(data, pos)
  ActiveMessage(
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
  let
    channel = readFixed[32](data, pos)
    inputs = readInputs(data, pos)
  finishDecode(data, pos)
  ChannelWithdrawPayload(channel: channel, inputs: inputs.noteIds)

func decodeChannelTransfer*(data: openArray[byte]): ChannelTransferPayload {.raises: [DecodingError].} =
  var pos = 0
  let
    channel = readFixed[32](data, pos)
    inputs = readInputs(data, pos)
    outputs = readOutputs(data, pos)
  finishDecode(data, pos)
  ChannelTransferPayload(
    channel: channel, inputs: inputs.noteIds, outputs: outputs.notes,
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

func decodeChannelConfig*(data: openArray[byte]): ChannelConfigPayload {.raises: [DecodingError].} =
  var pos = 0
  let channel = readFixed[32](data, pos)
  let keyCount = readLe[uint16](data, pos)
  var keys = newSeqOfCap[Ed25519PublicKey](keyCount)
  for _ in 0 ..< int(keyCount):
    var key: Ed25519PublicKey
    if not key.init(readFixed[EdPublicKeySize](data, pos)):
      raise newException(DecodingError, "invalid ChannelConfig Signer bytes")
    keys.add(key)
  let postingTimeframe = PostingTimeframe(readLe[uint32](data, pos))
  let postingTimeout = PostingTimeout(readLe[uint32](data, pos))
  let configurationThreshold = ConfigurationThreshold(readLe[uint16](data, pos))
  let transferThreshold = TransferThreshold(readLe[uint16](data, pos))
  finishDecode(data, pos)
  ChannelConfigPayload(
    channel: channel,
    keys: keys,
    postingTimeframe: postingTimeframe,
    postingTimeout: postingTimeout,
    configurationThreshold: configurationThreshold,
    transferThreshold: transferThreshold,
  )

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


func readOpPayload*(data: openArray[byte], pos: var int, opcode: Opcode): OpPayload {.raises: [DecodingError].} =
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
    let
      channel = readFixed[32](data, pos)
      inputs = readInputs(data, pos)
    OpPayload(
      kind: ChannelWithdraw,
      channelWithdraw: ChannelWithdrawPayload(
        channel: channel, inputs: inputs.noteIds,
      ),
    )
  of OpChannelTransfer:
    let
      channel = readFixed[32](data, pos)
      inputs = readInputs(data, pos)
      outputs = readOutputs(data, pos)
    OpPayload(
      kind: ChannelTransfer,
      channelTransfer: ChannelTransferPayload(
        channel: channel, inputs: inputs.noteIds, outputs: outputs.notes,
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
      sdpDeclare: DeclarationMessage(
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
      sdpWithdraw: WithdrawMessage(
        declarationId: declarationId, nonce: nonce, lockedNoteId: lockedNoteId,
      ),
    )
  of OpSdpActive:
    let declarationId = readFixed[32](data, pos)
    let nonce = readLe[uint64](data, pos)
    let metadata = readU32LeLenPrefixed(data, pos)
    OpPayload(
      kind: SdpActive,
      sdpActive: ActiveMessage(
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
    let channel = readFixed[32](data, pos)
    let keyCount = readLe[uint16](data, pos)
    var keys = newSeqOfCap[Ed25519PublicKey](keyCount)
    for _ in 0 ..< int(keyCount):
      var key: Ed25519PublicKey
      if not key.init(readFixed[EdPublicKeySize](data, pos)):
        raise newException(DecodingError, "invalid ChannelConfig Signer bytes")
      keys.add(key)
    let postingTimeframe = PostingTimeframe(readLe[uint32](data, pos))
    let postingTimeout = PostingTimeout(readLe[uint32](data, pos))
    let configurationThreshold = ConfigurationThreshold(readLe[uint16](data, pos))
    let transferThreshold = TransferThreshold(readLe[uint16](data, pos))
    OpPayload(
      kind: ChannelConfig,
      channelConfig: ChannelConfigPayload(
        channel: channel,
        keys: keys,
        postingTimeframe: postingTimeframe,
        postingTimeout: postingTimeout,
        configurationThreshold: configurationThreshold,
        transferThreshold: transferThreshold,
      ),
    )
  else:
    raise newException(DecodingError, "unsupported opcode for OpPayload decode: " & $opcode)

func readOp*(data: openArray[byte], pos: var int): Op {.raises: [DecodingError].} =
  let opcode = Opcode(readByte(data, pos))
  let payload = readOpPayload(data, pos, opcode)
  Op(opcode: opcode, payload: payload)

func decodeOp*(data: openArray[byte]): Op {.raises: [DecodingError].} =
  var pos = 0
  let res = readOp(data, pos)
  finishDecode(data, pos)
  res

func decodeOps*(data: openArray[byte]): seq[Op] {.raises: [DecodingError].} =
  var pos = 0
  let count = readByte(data, pos)
  var res = newSeqOfCap[Op](count)
  for _ in 0 ..< int(count):
    res.add readOp(data, pos)
  finishDecode(data, pos)
  res

func decodeOpPayload*(data: openArray[byte], opcode: Opcode): OpPayload {.raises: [DecodingError].} =
  var pos = 0
  let res = readOpPayload(data, pos, opcode)
  finishDecode(data, pos)
  res

{.pop.}
