# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  stew/byteutils,
  libp2p/multiaddress,
  libp2p/crypto/ed25519/ed25519,
  ./test_helpers,
  ../../../logos_chain/core/mantle/[operations, tx_types]

const SdpActiveSpecPayloadHex =
  # Payload from the Mantle specification's "Operation Id" table.
  "1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e" &
  "1f00000000000000" &
  "01" &
  "0a000000" &
  "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c" &
  "0202020202020202020202020202020202020202020202020202020202020202" &
  "0202020202020202020202020202020202020202020202020202020202020202" &
  "0202020202020202020202020202020202020202020202020202020202020202" &
  "0202020202020202020202020202020202020202020202020202020202020202" &
  "0202020202020202020202020202020202020202020202020202020202020202" &
  "0303030303030303030303030303030303030303030303030303030303030303"

suite "core/mantle/operations":
  proc mkSigner(seed: byte): Signer =
    var bytes: array[EdPublicKeySize, byte]
    bytes[0] = seed
    var key: Signer
    doAssert key.init(bytes)
    key

  test "Mantle opcode constants match expected wire values":
    check OpTransfer == 0x00'u8
    check OpChannelConfig == 0x10'u8
    check OpChannelInscribe == 0x11'u8
    check OpChannelDeposit == 0x12'u8
    check OpChannelWithdraw == 0x13'u8
    check OpChannelTransfer == 0x14'u8
    check OpSdpDeclare == 0x20'u8
    check OpSdpWithdraw == 0x21'u8
    check OpSdpActive == 0x22'u8
    check OpLeaderClaim == 0x30'u8

  test "opPayloadToOpcode round-trips kind":
    var transfer: TransferPayload
    var inscribe: ChannelInscribePayload
    var deposit: ChannelDepositPayload
    var withdraw: ChannelWithdrawPayload
    var channelTransfer: ChannelTransferPayload
    var sdpDeclare: DeclarationMessage
    var sdpWithdraw: WithdrawMessage
    var sdpActive: ActiveMessage
    var leaderClaim: LeaderClaimPayload
    var channelConfig: ChannelConfigPayload

    check opPayloadToOpcode(
      OpPayload(kind: Transfer, transfer: transfer)
    ) == OpTransfer
    check opPayloadToOpcode(
      OpPayload(kind: ChannelInscribe, channelInscribe: inscribe)
    ) == OpChannelInscribe
    check opPayloadToOpcode(
      OpPayload(kind: ChannelDeposit, channelDeposit: deposit)
    ) == OpChannelDeposit
    check opPayloadToOpcode(
      OpPayload(kind: ChannelWithdraw, channelWithdraw: withdraw)
    ) == OpChannelWithdraw
    check opPayloadToOpcode(
      OpPayload(kind: ChannelTransfer, channelTransfer: channelTransfer)
    ) == OpChannelTransfer
    check opPayloadToOpcode(
      OpPayload(kind: SdpDeclare, sdpDeclare: sdpDeclare)
    ) == OpSdpDeclare
    check opPayloadToOpcode(
      OpPayload(kind: SdpWithdraw, sdpWithdraw: sdpWithdraw)
    ) == OpSdpWithdraw
    check opPayloadToOpcode(
      OpPayload(kind: SdpActive, sdpActive: sdpActive)
    ) == OpSdpActive
    check opPayloadToOpcode(
      OpPayload(kind: LeaderClaim, leaderClaim: leaderClaim)
    ) == OpLeaderClaim
    check opPayloadToOpcode(
      OpPayload(kind: ChannelConfig, channelConfig: channelConfig)
    ) == OpChannelConfig

  test "encodeSdpDeclare uses wire ServiceType byte":
    let declare = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: default(ProviderId),
      zkId: default(ZkId),
      lockedNoteId: default(LockedNoteId),
    )
    let wire = encodeSdpDeclare(declare).get
    check wire.len > 0
    check wire[0] == encodeServiceType(ServiceType.bn)
    check wire[0] == byte(ord(ServiceType.bn))

  test "expectedOpProofKindForOpcode matches op families":
    check expectedOpProofKindForOpcode(OpTransfer).get == opfTransfer
    check expectedOpProofKindForOpcode(OpChannelInscribe).get == opfChannelInscribe
    check expectedOpProofKindForOpcode(OpSdpDeclare).get == opfSdpDeclare
    check expectedOpProofKindForOpcode(OpSdpWithdraw).get == opfSdpWithdraw
    check expectedOpProofKindForOpcode(OpSdpActive).get == opfSdpActive
    check expectedOpProofKindForOpcode(OpChannelDeposit).get == opfChannelDeposit
    check expectedOpProofKindForOpcode(OpChannelWithdraw).get == opfChannelWithdraw
    check expectedOpProofKindForOpcode(OpChannelTransfer).get == opfChannelTransfer
    check expectedOpProofKindForOpcode(OpLeaderClaim).get == opfLeaderClaim
    check expectedOpProofKindForOpcode(OpChannelConfig).get == opfChannelConfig
    check expectedOpProofKindForOpcode(Opcode(250)).error == EncodingError.UnsupportedOpcode

  test "create*Op constructors set opcode and payload kind":
    check createTransferOp(TransferPayload(
      inputs: Inputs(noteIds: @[]),
      outputs: Outputs(notes: @[]),
    )).opcode == OpTransfer

    check createChannelInscribeOp(ChannelInscribePayload(
      channelId: default(ChannelId),
      inscription: @[],
      parent: default(Parent),
      signer: default(Signer),
    )).opcode == OpChannelInscribe

    check createChannelDepositOp(ChannelDepositPayload(
      channel: default(ChannelId),
      inputs: Inputs(noteIds: @[]),
      metadata: @[],
    )).payload.kind == ChannelDeposit

    check createChannelWithdrawOp(ChannelWithdrawPayload(
      channel: default(ChannelId),
      inputs: Inputs(noteIds: @[]),
    )).payload.kind == ChannelWithdraw

    check createChannelTransferOp(ChannelTransferPayload(
      channel: default(ChannelId),
      inputs: Inputs(noteIds: @[]),
      outputs: Outputs(notes: @[]),
    )).payload.kind == ChannelTransfer

    check createSdpDeclareOp(DeclarationMessage(
      serviceType: default(ServiceType),
      locators: @[],
      providerId: default(ProviderId),
      zkId: default(ZkId),
      lockedNoteId: default(NoteId),
    )).opcode == OpSdpDeclare

    check createSdpWithdrawOp(WithdrawMessage(
      declarationId: default(DeclarationId),
      lockedNoteId: default(NoteId),
      nonce: default(Nonce),
    )).opcode == OpSdpWithdraw

    check createSdpActiveOp(ActiveMessage(
      declarationId: default(DeclarationId),
      nonce: default(Nonce),
      metadata: mkActivityProof(),
    )).opcode == OpSdpActive

    check createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(PublicKey),
    )).payload.kind == LeaderClaim

    check createChannelConfigOp(ChannelConfigPayload(
      channel: default(ChannelId),
      keys: @[],
      postingTimeframe: default(PostingTimeframe),
      postingTimeout: default(PostingTimeout),
      configurationThreshold: default(ConfigurationThreshold),
      transferThreshold: default(TransferThreshold),
    )).opcode == OpChannelConfig

  test "defaultOpForOpcode creates matching opcode and payload":
    let opcodes = [
      OpTransfer,
      OpChannelInscribe,
      OpChannelDeposit,
      OpChannelWithdraw,
      OpChannelTransfer,
      OpSdpDeclare,
      OpSdpWithdraw,
      OpSdpActive,
      OpLeaderClaim,
      OpChannelConfig,
    ]
    for opcode in opcodes:
      let op = defaultOpForOpcode(opcode).get
      check op.opcode == opcode
      check opPayloadToOpcode(op.payload) == opcode
    check defaultOpForOpcode(Opcode(250)).error == EncodingError.UnsupportedOpcode

  test "defaultOpProofForOpcode matches opcode proof kind":
    let opcodes = [
      OpTransfer,
      OpChannelInscribe,
      OpChannelDeposit,
      OpChannelWithdraw,
      OpChannelTransfer,
      OpSdpDeclare,
      OpSdpWithdraw,
      OpSdpActive,
      OpLeaderClaim,
      OpChannelConfig,
    ]
    for opcode in opcodes:
      let proof = defaultOpProofForOpcode(opcode).get
      check proof.kind == expectedOpProofKindForOpcode(opcode).get
    check defaultOpProofForOpcode(Opcode(250)).error == EncodingError.UnsupportedOpcode

  test "encodeOps prefixes op count and roundtrips with readOp":
    let
      ops = @[
        createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[]),
        )),
      ]
      encoded = encodeOps(ops).get
    check encoded.len >= 2
    check encoded[0] == 1'u8
    check encoded[1] == OpTransfer
    var pos = 0
    let count = readByte(encoded, pos).get
    check count == 1'u8
    var back: seq[Op]
    for _ in 0 ..< int(count):
      back.add readOp(encoded, pos).get
    check pos == encoded.len
    check back.len == 1
    check back[0].opcode == OpTransfer
    check back[0].payload.kind == Transfer

  test "encodeChannelDeposit and encodeChannelWithdraw include expected prefixes":
    let dep = encodeChannelDeposit(ChannelDepositPayload(
      channel: default(ChannelId),
      inputs: Inputs(noteIds: @[default(NoteId)]),
      metadata: @[],
    )).get
    check dep.len >= 32 + 1 + 32
    check dep[32] == 1'u8 # InputCount

    let wdr = encodeChannelWithdraw(ChannelWithdrawPayload(
      channel: default(ChannelId),
      inputs: Inputs(noteIds: @[default(NoteId)]),
    )).get
    check wdr.len == 32 + 1 + 32
    check wdr[32] == 1'u8 # InputCount

  test "encodeChannelTransfer lays out ChannelId, Inputs then Outputs":
    let wire = encodeChannelTransfer(ChannelTransferPayload(
      channel: default(ChannelId),
      inputs: Inputs(noteIds: @[default(NoteId)]),
      outputs: Outputs(notes: @[Note(value: 7, zkPublicKey: default(ZkPublicKey))]),
    )).get
    check wire.len == 32 + 1 + 32 + 1 + 40
    check wire[32] == 1'u8 # InputCount
    check wire[65] == 1'u8 # OutputCount
    check wire[66] == 7'u8 # Value LE low byte

  test "encodeChannelConfig uses UINT16 KeyCount and roundtrips with readOpPayload":
    var keys: seq[Signer]
    for i in 0 ..< 256:
      keys.add mkSigner(byte(i))
    let
      cfgPayload = ChannelConfigPayload(
        channel: default(ChannelId),
        parent: hexToByteArray[32](
          "0505050505050505050505050505050505050505050505050505050505050505"),
        keys: keys,
        postingTimeframe: 42'u32,
        postingTimeout: 7'u32,
        configurationThreshold: 3'u16,
        transferThreshold: 5'u16,
      )
      wire = encodeChannelConfig(cfgPayload).get
    check wire.len == 32 + 32 + 2 + (256 * 32) + 4 + 4 + 2 + 2
    check wire[32] == 5'u8 # Parent follows ChannelId
    check wire[64] == 0'u8
    check wire[65] == 1'u8 # KeyCount 256 as UINT16 LE
    var pos = 0
    let cfgBack = readOpPayload(wire, pos, OpChannelConfig).get.channelConfig
    check pos == wire.len
    check cfgBack.channel == cfgPayload.channel
    check cfgBack.parent == cfgPayload.parent
    check cfgBack.keys.len == 256
    check cfgBack.postingTimeframe == cfgPayload.postingTimeframe
    check cfgBack.postingTimeout == cfgPayload.postingTimeout
    check cfgBack.configurationThreshold == cfgPayload.configurationThreshold
    check cfgBack.transferThreshold == cfgPayload.transferThreshold

  test "readOpPayload decodes the CHANNEL_CONFIG spec vector, parent included":
    let wire = hexToSeqByte(
      "0707070707070707070707070707070707070707070707070707070707070707" &
      "0000000000000000000000000000000000000000000000000000000000000000" &
      "0200" &
      "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca" &
      "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618" &
      "0a000000" & "0b000000" & "0c00" & "0d00")
    var pos = 0
    let cfg = readOpPayload(wire, pos, OpChannelConfig).get.channelConfig
    check pos == wire.len
    check cfg.channel.toHex ==
      "0707070707070707070707070707070707070707070707070707070707070707"
    check cfg.parent == default(Hash32)
    check cfg.keys.len == 2
    check cfg.keys[0].getBytes.toHex ==
      "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca"
    check cfg.keys[1].getBytes.toHex ==
      "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618"
    check cfg.postingTimeframe == 10
    check cfg.postingTimeout == 11
    check cfg.configurationThreshold == 12
    check cfg.transferThreshold == 13

  test "readOp and readOpPayload roundtrip all 10 operation variants":
    let
      # 1. Transfer
      opTransfer = createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[default(NoteId)]),
        outputs: Outputs(notes: @[Note(value: 42, zkPublicKey: default(ZkPublicKey))]),
      ))
      # 2. ChannelInscribe
      opInscribe = createChannelInscribeOp(ChannelInscribePayload(
        channelId: default(ChannelId),
        inscription: @[1'u8, 2, 3],
        parent: default(Parent),
        signer: mkSigner(1),
      ))
      # 3. ChannelDeposit
      opDeposit = createChannelDepositOp(ChannelDepositPayload(
        channel: default(ChannelId),
        inputs: Inputs(noteIds: @[default(NoteId)]),
        metadata: @[4'u8, 5],
      ))
      # 4. ChannelWithdraw
      opWithdraw = createChannelWithdrawOp(ChannelWithdrawPayload(
        channel: default(ChannelId),
        inputs: Inputs(noteIds: @[default(NoteId)]),
      ))
      # 5. ChannelTransfer
      opChannelTransfer = createChannelTransferOp(ChannelTransferPayload(
        channel: default(ChannelId),
        inputs: Inputs(noteIds: @[default(NoteId)]),
        outputs: Outputs(notes: @[Note(value: 99, zkPublicKey: default(ZkPublicKey))]),
      ))
      # 6. SdpDeclare
      opSdpDeclare = createSdpDeclareOp(DeclarationMessage(
        serviceType: ServiceType.bn,
        locators: @[MultiAddress.init("/ip4/127.0.0.1/tcp/1234").tryGet()],
        providerId: mkSigner(2),
        zkId: default(ZkId),
        lockedNoteId: default(LockedNoteId),
      ))
      # 7. SdpWithdraw
      opSdpWithdraw = createSdpWithdrawOp(WithdrawMessage(
        declarationId: default(DeclarationId),
        nonce: 123'u64,
        lockedNoteId: default(LockedNoteId),
      ))
      # 8. SdpActive
      opSdpActive = createSdpActiveOp(ActiveMessage(
        declarationId: default(DeclarationId),
        nonce: 456'u64,
        metadata: mkActivityProof(),
      ))
      # 9. LeaderClaim
      opLeaderClaim = createLeaderClaimOp(LeaderClaimPayload(
        rewardsRoot: default(RewardsRoot),
        voucherNullifier: default(VoucherNullifier),
        publicKey: default(ZkPublicKey),
      ))
      # 10. ChannelConfig
      opChannelConfig = createChannelConfigOp(ChannelConfigPayload(
        channel: default(ChannelId),
        keys: @[mkSigner(3)],
        postingTimeframe: 10,
        postingTimeout: 20,
        configurationThreshold: 1,
        transferThreshold: 1,
      ))

      allOps = [
        opTransfer, opInscribe, opDeposit, opWithdraw, opChannelTransfer,
        opSdpDeclare, opSdpWithdraw, opSdpActive, opLeaderClaim, opChannelConfig,
      ]

    for op in allOps:
      # Test readOp
      let wire = encodeOp(op).get
      var pos = 0
      let backOp = readOp(wire, pos).get
      check pos == wire.len
      check backOp.opcode == op.opcode
      check backOp.payload.kind == op.payload.kind
      check byteLen(backOp) == wire.len

      # Test readOpPayload directly on payload slice
      var payloadPos = 0
      let payloadWire = wire[1 .. ^1]
      let backPayload = readOpPayload(payloadWire, payloadPos, op.opcode).get
      check payloadPos == payloadWire.len
      check backPayload.kind == op.payload.kind

  test "SDP_ACTIVE encodes the spec vector":
    check encodeSdpActive(mkSpecActiveMessage()).toHex == SdpActiveSpecPayloadHex

  test "readOpPayload decodes the SDP_ACTIVE spec vector":
    let payload = hexToSeqByte(SdpActiveSpecPayloadHex)
    var pos = 0
    let decoded = readOpPayload(payload, pos, OpSdpActive).get
    check pos == 269
    check decoded.kind == SdpActive
    check decoded.sdpActive == mkSpecActiveMessage()

  test "readOpPayload rejects an unknown activity metadata type":
    for tag in [0x00'u8, 0x02]:
      var
        payload = hexToSeqByte(SdpActiveSpecPayloadHex)
        pos = 0
      payload[40] = tag
      check readOpPayload(payload, pos, OpSdpActive).error ==
        DecodingError.UnknownActivityMetadataType

  test "readOpPayload rejects a CHANNEL_INSCRIBE inscription over MaxOperationDataSize":
    var payload = newSeq[byte](32)
    payload.add encodeLe(uint32(MaxOperationDataSize + 1))
    var pos = 0
    check readOpPayload(payload, pos, OpChannelInscribe).error ==
      DecodingError.OperationDataExceeded

  test "readOpPayload rejects CHANNEL_DEPOSIT metadata over MaxOperationDataSize":
    # ChannelId || InputCount 0 || oversized DepositMetadata prefix
    var payload = newSeq[byte](32)
    payload.add 0'u8
    payload.add encodeLe(uint32(MaxOperationDataSize + 1))
    var pos = 0
    check readOpPayload(payload, pos, OpChannelDeposit).error ==
      DecodingError.OperationDataExceeded

  test "readOp returns UnsupportedOpcode on unknown opcode byte":
    var pos = 0
    check readOp([250'u8], pos).error == DecodingError.UnsupportedOpcode

  test "readOpPayload returns UnsupportedOpcode on unknown opcode":
    var pos = 0
    check readOpPayload([], pos, Opcode(250)).error == DecodingError.UnsupportedOpcode

  test "encodeOps returns OpsCountExceeded when ops count exceeds 255":
    var largeOps: seq[Op]
    let dummyOp = createTransferOp(TransferPayload(
      inputs: Inputs(noteIds: @[]),
      outputs: Outputs(notes: @[]),
    ))
    for i in 0 .. 256:
      largeOps.add dummyOp
    check encodeOps(largeOps).error == EncodingError.OpsCountExceeded

  test "encodeChannelConfig returns KeysCountExceeded when keys count exceeds 65535":
    var largeKeys: seq[Signer]
    let signer = mkSigner(1)
    largeKeys.setLen(65536)
    for i in 0 ..< 65536:
      largeKeys[i] = signer
    let cfg = ChannelConfigPayload(
      channel: default(ChannelId),
      keys: largeKeys,
      postingTimeframe: 1,
      postingTimeout: 1,
      configurationThreshold: 1,
      transferThreshold: 1,
    )
    check encodeChannelConfig(cfg).error == EncodingError.KeysCountExceeded

{.pop.}
