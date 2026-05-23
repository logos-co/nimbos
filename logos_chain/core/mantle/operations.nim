# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [v1.4 Mantle](https://nomos-tech.notion.site/v1-4-Mantle-335261aa09df8065a38acff4b25aee82)
##
## Wire encoding/decoding: [v1.3 Mantle Transaction Encoding](https://nomos-tech.notion.site/v1-3-Mantle-Transaction-Encoding-335261aa09df8051a8a6f325aa41f6a7)

{.push raises: [], gcsafe.}

import ./[primitives, opcodes]
import ../crypto/types
import libp2p/crypto/ed25519/ed25519
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
    outputs*: seq[Note]
    opIdNonce*: uint32


type
  SdpDeclarePayload* = object
    serviceType*: ServiceType
    locators*: seq[Locator]
    providerId*: ProviderId
    zkId*: ZkId
    lockedNoteId*: NoteId

  SdpWithdrawPayload* = object
    declarationId*: DeclarationId
    lockedNoteId*: NoteId
    nonce*: Nonce

  SdpActivePayload* = object
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
    withdrawThreshold*: WithdrawThreshold


type
  OpPayloadTag* = enum
    Transfer
    ChannelInscribe
    ChannelDeposit
    ChannelWithdraw
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
    of SdpDeclare: sdpDeclare*: SdpDeclarePayload
    of SdpWithdraw: sdpWithdraw*: SdpWithdrawPayload
    of SdpActive: sdpActive*: SdpActivePayload
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

func createSdpDeclareOp*(payload: SdpDeclarePayload): Op =
  Op(opcode: OpSdpDeclare, payload: OpPayload(kind: SdpDeclare, sdpDeclare: payload))

func createSdpWithdrawOp*(payload: SdpWithdrawPayload): Op =
  Op(
    opcode: OpSdpWithdraw,
    payload: OpPayload(kind: SdpWithdraw, sdpWithdraw: payload),
  )

func createSdpActiveOp*(payload: SdpActivePayload): Op =
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
  of SdpDeclare: OpSdpDeclare
  of SdpWithdraw: OpSdpWithdraw
  of SdpActive: OpSdpActive
  of LeaderClaim: OpLeaderClaim
  of ChannelConfig: OpChannelConfig

func isSupportedOpcode*(opcode: Opcode): bool =
  ## True when opcode is part of the currently supported Mantle operation set.
  case opcode
  of OpTransfer, OpChannelInscribe, OpChannelDeposit, OpChannelWithdraw,
     OpSdpDeclare, OpSdpWithdraw, OpSdpActive, OpLeaderClaim, OpChannelConfig:
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
      outputs: @[],
      opIdNonce: 0'u32,
    ))
  of OpSdpDeclare:
    createSdpDeclareOp(SdpDeclarePayload(
      serviceType: default(ServiceType),
      locators: @[],
      providerId: default(ProviderId),
      zkId: default(ZkId),
      lockedNoteId: default(LockedNoteId),
    ))
  of OpSdpWithdraw:
    createSdpWithdrawOp(SdpWithdrawPayload(
      declarationId: default(DeclarationId),
      nonce: default(Nonce),
      lockedNoteId: default(LockedNoteId),
    ))
  of OpSdpActive:
    createSdpActiveOp(SdpActivePayload(
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
      withdrawThreshold: default(WithdrawThreshold),
    ))
  else:
    doAssert false, "unknown opcode for default op: " & $opcode
    default(Op)

func encodeTransfer*(value: TransferPayload): seq[byte] =
  ## Transfer = Inputs || Outputs
  result = encodeInputs(value.inputs)
  result.add(encodeOutputs(value.outputs))

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
  result[0 ..< 32] = encodeDeclarationId(value.declarationId)
  result[32 ..< 40] = encodeNonce(value.nonce)
  result[40 ..< 72] = encodeLockedNoteId(value.lockedNoteId)

func encodeSdpActive*(value: SdpActivePayload): seq[byte] =
  ## SDPActive = DeclarationId || Nonce || Metadata
  result = @(encodeDeclarationId(value.declarationId))
  result.add(encodeNonce(value.nonce))
  result.add(encodeMetadata(value.metadata))

func encodeLeaderClaim*(value: LeaderClaimPayload): array[96, byte] =
  ## LeaderClaim = RewardsRoot || VoucherNullifier || PublicKey
  result[0 ..< 32] = encodeRewardsRoot(value.rewardsRoot)
  result[32 ..< 64] = encodeVoucherNullifier(value.voucherNullifier)
  result[64 ..< 96] = encodePublicKey(value.publicKey)

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

func decodeTransfer*(data: openArray[byte]): TransferPayload {.raises: [DecodingError].} =
  var pos = 0
  let inputs = readInputs(data, pos)
  let outputs = readOutputs(data, pos)
  finishDecode(data, pos)
  TransferPayload(inputs: inputs, outputs: outputs)

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


proc readOpPayload*(data: openArray[byte], pos: var int, opcode: Opcode): OpPayload {.raises: [DecodingError].} =
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

proc readOp*(data: openArray[byte], pos: var int): Op {.raises: [DecodingError].} =
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

func decodeOpPayload*(data: openArray[byte], opcode: Opcode): OpPayload {.raises: [DecodingError].} =
  var pos = 0
  result = readOpPayload(data, pos, opcode)
  finishDecode(data, pos)

{.pop.}
