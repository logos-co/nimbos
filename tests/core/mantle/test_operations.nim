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
  libp2p/crypto/ed25519/ed25519,
  ../../../logos_chain/core/mantle/[operations, tx_types]

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
    check OpSdpDeclare == 0x20'u8
    check OpSdpWithdraw == 0x21'u8
    check OpSdpActive == 0x22'u8
    check OpLeaderClaim == 0x30'u8

  test "opPayloadToOpcode round-trips kind":
    var transfer: TransferPayload
    var inscribe: ChannelInscribePayload
    var deposit: ChannelDepositPayload
    var withdraw: ChannelWithdrawPayload
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
    let wire = encodeSdpDeclare(declare)
    check wire.len > 0
    check wire[0] == encodeServiceType(ServiceType.bn)
    check wire[0] == byte(ord(ServiceType.bn))

  test "expectedOpProofKindForOpcode matches op families":
    check expectedOpProofKindForOpcode(OpTransfer) == opfTransfer
    check expectedOpProofKindForOpcode(OpChannelInscribe) == opfChannelInscribe
    check expectedOpProofKindForOpcode(OpSdpDeclare) == opfSdpDeclare
    check expectedOpProofKindForOpcode(OpSdpWithdraw) == opfSdpWithdraw
    check expectedOpProofKindForOpcode(OpSdpActive) == opfSdpActive
    check expectedOpProofKindForOpcode(OpChannelDeposit) == opfChannelDeposit
    check expectedOpProofKindForOpcode(OpChannelWithdraw) == opfChannelWithdraw
    check expectedOpProofKindForOpcode(OpLeaderClaim) == opfLeaderClaim
    check expectedOpProofKindForOpcode(OpChannelConfig) == opfChannelConfig

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
      inputs: @[],
      metadata: @[],
    )).payload.kind == ChannelDeposit

    check createChannelWithdrawOp(ChannelWithdrawPayload(
      channel: default(ChannelId),
      outputs: @[],
      opIdNonce: 0'u32,
    )).payload.kind == ChannelWithdraw

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
      withdrawThreshold: default(WithdrawThreshold),
    )).opcode == OpChannelConfig

  test "defaultOpForOpcode creates matching opcode and payload":
    let opcodes = [
      OpTransfer,
      OpChannelInscribe,
      OpChannelDeposit,
      OpChannelWithdraw,
      OpSdpDeclare,
      OpSdpWithdraw,
      OpSdpActive,
      OpLeaderClaim,
      OpChannelConfig,
    ]
    for opcode in opcodes:
      let op = defaultOpForOpcode(opcode)
      check op.opcode == opcode
      check opPayloadToOpcode(op.payload) == opcode

  test "defaultOpProofForOpcode matches opcode proof kind":
    let opcodes = [
      OpTransfer,
      OpChannelInscribe,
      OpChannelDeposit,
      OpChannelWithdraw,
      OpSdpDeclare,
      OpSdpWithdraw,
      OpSdpActive,
      OpLeaderClaim,
      OpChannelConfig,
    ]
    for opcode in opcodes:
      let proof = defaultOpProofForOpcode(opcode)
      check proof.kind == expectedOpProofKindForOpcode(opcode)

  test "encodeOps prefixes op count and includes opcode":
    let
      ops = @[
        createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[]),
        )),
      ]
      encoded = encodeOps(ops)
    check encoded.len >= 2
    check encoded[0] == 1'u8
    check encoded[1] == OpTransfer

  test "encodeChannelDeposit and encodeChannelWithdraw include expected prefixes":
    let dep = encodeChannelDeposit(ChannelDepositPayload(
      channel: default(ChannelId),
      inputs: @[default(NoteId)],
      metadata: @[],
    ))
    check dep.len >= 32 + 1 + 32
    check dep[32] == 1'u8 # InputCount

    let wdr = encodeChannelWithdraw(ChannelWithdrawPayload(
      channel: default(ChannelId),
      outputs: @[],
      opIdNonce: 1'u32,
    ))
    check wdr.len == 32 + 1 + 4
    check wdr[^4] == 1'u8 # opIdNonce LE low byte

  test "decodeOps roundtrips encodeOps":
    let
      ops = @[
        createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[]),
        )),
      ]
      wire = encodeOps(ops)
      back = decodeOps(wire)
    check back.len == 1
    check back[0].opcode == OpTransfer
    check back[0].payload.kind == Transfer

  test "decodeChannelDeposit and decodeChannelWithdraw roundtrip encoders":
    let
      depPayload = ChannelDepositPayload(
        channel: default(ChannelId),
        inputs: @[default(NoteId)],
        metadata: @[],
      )
      depWire = encodeChannelDeposit(depPayload)
      depBack = decodeChannelDeposit(depWire)
    check depBack.channel == depPayload.channel
    check depBack.inputs == depPayload.inputs
    check depBack.metadata == depPayload.metadata

    let
      wdrPayload = ChannelWithdrawPayload(
        channel: default(ChannelId),
        outputs: @[],
        opIdNonce: 1'u32,
      )
      wdrWire = encodeChannelWithdraw(wdrPayload)
      wdrBack = decodeChannelWithdraw(wdrWire)
    check wdrBack.channel == wdrPayload.channel
    check wdrBack.outputs == wdrPayload.outputs
    check wdrBack.opIdNonce == wdrPayload.opIdNonce

  test "encodeChannelConfig uses UINT16 KeyCount and roundtrips":
    var keys: seq[Signer]
    for i in 0 ..< 256:
      keys.add mkSigner(byte(i))
    let cfgPayload = ChannelConfigPayload(
      channel: default(ChannelId),
      keys: keys,
      postingTimeframe: 42'u32,
      postingTimeout: 7'u32,
      configurationThreshold: 3'u16,
      withdrawThreshold: 5'u16,
    )
    let wire = encodeChannelConfig(cfgPayload)
    check wire.len == 32 + 2 + (256 * 32) + 4 + 4 + 2 + 2
    check wire[32] == 0'u8
    check wire[33] == 1'u8 # KeyCount 256 as UINT16 LE
    let cfgBack = decodeChannelConfig(wire)
    check cfgBack.channel == cfgPayload.channel
    check cfgBack.keys.len == 256
    check cfgBack.postingTimeframe == cfgPayload.postingTimeframe
    check cfgBack.postingTimeout == cfgPayload.postingTimeout
    check cfgBack.configurationThreshold == cfgPayload.configurationThreshold
    check cfgBack.withdrawThreshold == cfgPayload.withdrawThreshold

  test "decodeOp roundtrips ChannelConfig through encodeOp":
    let op = createChannelConfigOp(ChannelConfigPayload(
      channel: default(ChannelId),
      keys: @[mkSigner(9)],
      postingTimeframe: 1'u32,
      postingTimeout: 2'u32,
      configurationThreshold: 3'u16,
      withdrawThreshold: 4'u16,
    ))
    let wire = encodeOp(op)
    let back = decodeOp(wire)
    check back.opcode == OpChannelConfig
    check back.payload.kind == ChannelConfig
    check back.payload.channelConfig.keys.len == 1
    check back.payload.channelConfig.postingTimeframe == 1'u32

{.pop.}
