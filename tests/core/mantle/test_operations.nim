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
  libp2p/multiaddress,
  libp2p/crypto/ed25519/ed25519,
  ../../../logos_chain/core/mantle/tx_types

suite "core/mantle/operations":
  proc mkSigner(seed: byte): Signer =
    var bytes: array[EdPublicKeySize, byte]
    bytes[0] = seed
    var key: Signer
    doAssert key.init(bytes)
    key

  test "Mantle opcode constants match expected wire values":
    check:
      OpTransfer == 0x00'u8
      OpChannelConfig == 0x10'u8
      OpChannelInscribe == 0x11'u8
      OpChannelDeposit == 0x12'u8
      OpChannelWithdraw == 0x13'u8
      OpChannelTransfer == 0x14'u8
      OpSdpDeclare == 0x20'u8
      OpSdpWithdraw == 0x21'u8
      OpSdpActive == 0x22'u8
      OpLeaderClaim == 0x30'u8

  test "opPayloadToOpcode round-trips kind":
    var
      transfer: TransferPayload
      inscribe: ChannelInscribePayload
      deposit: ChannelDepositPayload
      withdraw: ChannelWithdrawPayload
      channelTransfer: ChannelTransferPayload
      sdpDeclare: DeclarationMessage
      sdpWithdraw: WithdrawMessage
      sdpActive: ActiveMessage
      leaderClaim: LeaderClaimPayload
      channelConfig: ChannelConfigPayload

    check:
      opPayloadToOpcode(
        OpPayload(kind: Transfer, transfer: transfer)
      ) == OpTransfer
      opPayloadToOpcode(
        OpPayload(kind: ChannelInscribe, channelInscribe: inscribe)
      ) == OpChannelInscribe
      opPayloadToOpcode(
        OpPayload(kind: ChannelDeposit, channelDeposit: deposit)
      ) == OpChannelDeposit
      opPayloadToOpcode(
        OpPayload(kind: ChannelWithdraw, channelWithdraw: withdraw)
      ) == OpChannelWithdraw
      opPayloadToOpcode(
        OpPayload(kind: ChannelTransfer, channelTransfer: channelTransfer)
      ) == OpChannelTransfer
      opPayloadToOpcode(
        OpPayload(kind: SdpDeclare, sdpDeclare: sdpDeclare)
      ) == OpSdpDeclare
      opPayloadToOpcode(
        OpPayload(kind: SdpWithdraw, sdpWithdraw: sdpWithdraw)
      ) == OpSdpWithdraw
      opPayloadToOpcode(
        OpPayload(kind: SdpActive, sdpActive: sdpActive)
      ) == OpSdpActive
      opPayloadToOpcode(
        OpPayload(kind: LeaderClaim, leaderClaim: leaderClaim)
      ) == OpLeaderClaim
      opPayloadToOpcode(
        OpPayload(kind: ChannelConfig, channelConfig: channelConfig)
      ) == OpChannelConfig

  test "encodeSdpDeclare uses wire ServiceType byte":
    let
      declare = DeclarationMessage(
        serviceType: ServiceType.bn,
        locators: @[],
        providerId: default(ProviderId),
        zkId: default(ZkId),
        lockedNoteId: default(LockedNoteId),
      )
      wire = encodeSdpDeclare(declare).get
    check:
      wire.len > 0
      wire[0] == encodeServiceType(ServiceType.bn)
      wire[0] == byte(ord(ServiceType.bn))

  test "expectedOpProofKindForOpcode matches op families":
    check:
      expectedOpProofKindForOpcode(OpTransfer).get == opfTransfer
      expectedOpProofKindForOpcode(OpChannelInscribe).get == opfChannelInscribe
      expectedOpProofKindForOpcode(OpSdpDeclare).get == opfSdpDeclare
      expectedOpProofKindForOpcode(OpSdpWithdraw).get == opfSdpWithdraw
      expectedOpProofKindForOpcode(OpSdpActive).get == opfSdpActive
      expectedOpProofKindForOpcode(OpChannelDeposit).get == opfChannelDeposit
      expectedOpProofKindForOpcode(OpChannelWithdraw).get == opfChannelWithdraw
      expectedOpProofKindForOpcode(OpChannelTransfer).get == opfChannelTransfer
      expectedOpProofKindForOpcode(OpLeaderClaim).get == opfLeaderClaim
      expectedOpProofKindForOpcode(OpChannelConfig).get == opfChannelConfig
      expectedOpProofKindForOpcode(Opcode(250)).error == EncodingError.UnsupportedOpcode

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
      metadata: @[],
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
    const opcodes = [
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
      check:
        op.opcode == opcode
        opPayloadToOpcode(op.payload) == opcode
    check defaultOpForOpcode(Opcode(250)).error == EncodingError.UnsupportedOpcode

  test "defaultOpProofForOpcode matches opcode proof kind":
    const opcodes = [
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
    check:
      encoded.len >= 2
      encoded[0] == 1'u8
      encoded[1] == OpTransfer
    var pos = 0
    let count = readByte(encoded, pos).get
    check count == 1'u8
    var back: seq[Op]
    for _ in 0 ..< int(count):
      back.add readOp(encoded, pos).get
    check:
      pos == encoded.len
      back.len == 1
      back[0].opcode == OpTransfer
      back[0].payload.kind == Transfer

  test "encodeChannelDeposit and encodeChannelWithdraw include expected prefixes":
    let dep = encodeChannelDeposit(ChannelDepositPayload(
      channel: default(ChannelId),
      inputs: Inputs(noteIds: @[default(NoteId)]),
      metadata: @[],
    )).get
    check:
      dep.len >= 32 + 1 + 32
      dep[32] == 1'u8 # InputCount

    let wdr = encodeChannelWithdraw(ChannelWithdrawPayload(
      channel: default(ChannelId),
      inputs: Inputs(noteIds: @[default(NoteId)]),
    )).get
    check:
      wdr.len == 32 + 1 + 32
      wdr[32] == 1'u8 # InputCount

  test "encodeChannelTransfer lays out ChannelId, Inputs then Outputs":
    let wire = encodeChannelTransfer(ChannelTransferPayload(
      channel: default(ChannelId),
      inputs: Inputs(noteIds: @[default(NoteId)]),
      outputs: Outputs(notes: @[Note(value: 7, zkPublicKey: default(ZkPublicKey))]),
    )).get
    check:
      wire.len == 32 + 1 + 32 + 1 + 40
      wire[32] == 1'u8 # InputCount
      wire[65] == 1'u8 # OutputCount
      wire[66] == 7'u8 # Value LE low byte

  test "encodeChannelConfig uses UINT16 KeyCount and roundtrips with readOpPayload":
    var keys: seq[Signer]
    for i in 0 ..< 256:
      keys.add mkSigner(byte(i))
    let
      cfgPayload = ChannelConfigPayload(
        channel: default(ChannelId),
        keys: keys,
        postingTimeframe: 42'u32,
        postingTimeout: 7'u32,
        configurationThreshold: 3'u16,
        transferThreshold: 5'u16,
      )
      wire = encodeChannelConfig(cfgPayload).get
    check:
      wire.len == 32 + 2 + (256 * 32) + 4 + 4 + 2 + 2
      wire[32] == 0'u8
      wire[33] == 1'u8 # KeyCount 256 as UINT16 LE
    var pos = 0
    let cfgBack = readOpPayload(wire, pos, OpChannelConfig).get.channelConfig
    check:
      pos == wire.len
      cfgBack.channel == cfgPayload.channel
      cfgBack.keys.len == 256
      cfgBack.postingTimeframe == cfgPayload.postingTimeframe
      cfgBack.postingTimeout == cfgPayload.postingTimeout
      cfgBack.configurationThreshold == cfgPayload.configurationThreshold
      cfgBack.transferThreshold == cfgPayload.transferThreshold

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
        metadata: @[7'u8, 8, 9],
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
      check:
        pos == wire.len
        backOp.opcode == op.opcode
        backOp.payload.kind == op.payload.kind
        byteLen(backOp) == wire.len

      # Test readOpPayload directly on payload slice
      var payloadPos = 0
      let
        payloadWire = wire[1 .. ^1]
        backPayload = readOpPayload(payloadWire, payloadPos, op.opcode).get
      check:
        payloadPos == payloadWire.len
        backPayload.kind == op.payload.kind

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
