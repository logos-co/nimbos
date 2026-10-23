# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/algorithm,
  unittest2,
  stew/byteutils,
  libp2p/crypto/ed25519/ed25519,
  ./test_helpers,
  ../../../logos_chain/core/mantle/[operations, tx_hashing, tx_types, utxo]

const OneOfEachPayloadHex =
  # Payload of the Mantle specification's "Transaction with one of each
  # operation" vector, one group of lines for each operation.
  # op count
  "0a" &
  # TRANSFER
  "0002010000000000000000000000000000000000000000000000000000000000" &
  "0000020000000000000000000000000000000000000000000000000000000000" &
  "0000020300000000000000040000000000000000000000000000000000000000" &
  "0000000000000000000000050000000000000006000000000000000000000000" &
  "00000000000000000000000000000000000000" &
  # CHANNEL_CONFIG
  "1007070707070707070707070707070707070707070707070707070707070707" &
  "0700000000000000000000000000000000000000000000000000000000000000" &
  "0002001398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd1" &
  "7d93cafd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835" &
  "e9f6180a0000000b0000000c000d00" &
  # CHANNEL_INSCRIBE
  "110e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e" &
  "0e0b00000068656c6c6f206c6f676f7300000000000000000000000000000000" &
  "00000000000000000000000000000000d9bf2148748a85c89da5aad8ee0b0fc2" &
  "d105fd39d41a4c796536354f0ae2900c" &
  # CHANNEL_DEPOSIT
  "1210101010101010101010101010101010101010101010101010101010101010" &
  "1001110000000000000000000000000000000000000000000000000000000000" &
  "0000100000006465706f7369742d6d65746164617461" &
  # CHANNEL_WITHDRAW
  "1312121212121212121212121212121212121212121212121212121212121212" &
  "1201130000000000000000000000000000000000000000000000000000000000" &
  "0000" &
  # CHANNEL_TRANSFER
  "1414141414141414141414141414141414141414141414141414141414141414" &
  "1401150000000000000000000000000000000000000000000000000000000000" &
  "0000011600000000000000170000000000000000000000000000000000000000" &
  "0000000000000000000000" &
  # SDP_DECLARE
  "2000010b00047f00000191020bb8cd0353470962558a6e0839022ae65c6b2723" &
  "b32772e5c0c5f4776cb8e6a3e10ba2f319000000000000000000000000000000" &
  "000000000000000000000000000000001a000000000000000000000000000000" &
  "00000000000000000000000000000000" &
  # SDP_WITHDRAW
  "211b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b" &
  "1b1d000000000000001c00000000000000000000000000000000000000000000" &
  "000000000000000000" &
  # SDP_ACTIVE
  "221e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e" &
  "1e1f00000000000000010a0000008a88e3dd7409f195fd52db2d3cba5d72ca67" &
  "09bf1d94121bf3748801b40f6f5c020202020202020202020202020202020202" &
  "0202020202020202020202020202020202020202020202020202020202020202" &
  "0202020202020202020202020202020202020202020202020202020202020202" &
  "0202020202020202020202020202020202020202020202020202020202020202" &
  "0202020202020202020202020202020202020202020202020202020202020202" &
  "0202020202020202020202020202030303030303030303030303030303030303" &
  "0303030303030303030303030303" &
  # LEADER_CLAIM
  "3020000000000000000000000000000000000000000000000000000000000000" &
  "0021000000000000000000000000000000000000000000000000000000000000" &
  "0022000000000000000000000000000000000000000000000000000000000000" &
  "00"

proc mkProvider(seed: byte): ProviderId =
  var bytes: array[EdPublicKeySize, byte]
  bytes[0] = seed
  var key: ProviderId
  doAssert key.init(bytes)
  key

func filledHash32(b: byte): Hash32 =
  ## The spec's test vectors use channel ids whose every byte repeats.
  var h: Hash32
  h.fill(b)
  h

func smallFe(b: byte): FieldElement =
  ## Field element `b`, i.e. byte `b` followed by 31 zero bytes on the wire.
  frFromBytesLE([b]).get

suite "core/mantle/tx_hashing":
  test "mantleTxHash is sensitive to tx bytes":
    let txA = MantleTx(
      ops: @[
        createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[]),
        )),
      ],
    )
    let txB = MantleTx(ops: @[])
    check mantleTxHash(txA).get != mantleTxHash(txB).get

  test "mantleTxHash is deterministic":
    let tx = MantleTx(ops: @[])
    check mantleTxHash(tx).get == mantleTxHash(tx).get

  test "empty transaction spec vector":
    let tx = MantleTx(ops: @[])
    check encodeMantleTx(tx).get.toHex == "00"
    check mantleTxHash(tx).get.toHex ==
      "2eba3f667b80a508f3d44d149a1c27a90ea365a51e4fc8209289088142b364e5"

  test "transaction with one of each operation spec vector":
    let payload = hexToSeqByte(OneOfEachPayloadHex)
    var pos = 0
    let tx = readMantleTx(payload, pos).expect("spec vector decodes")
    check pos == payload.len
    check encodeMantleTx(tx).get == payload
    check mantleTxHash(tx).get.toHex ==
      "01d051d472817b7b6dfd18ff9a6cc5160579c5dad22aa000db527263af851edb"

  test "sdp opId is deterministic and payload-sensitive":
    let utxo = mkUtxo(pkSeed = 1)
    let otherUtxo = mkUtxo(pkSeed = 2)
    let declare = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: mkProvider(1),
      lockedNoteId: id(utxo),
      zkId: utxo.note.zkPublicKey,
    )
    check opId(declare).get == opId(declare).get
    check opId(declare).get != opId(DeclarationMessage(
      serviceType: declare.serviceType,
      locators: declare.locators,
      providerId: declare.providerId,
      lockedNoteId: id(otherUtxo),
      zkId: declare.zkId,
    )).get

    var declarationId: DeclarationId
    declarationId[0] = 4'u8
    let withdraw = WithdrawMessage(
      declarationId: declarationId,
      lockedNoteId: id(utxo),
      nonce: 1'u64,
    )
    check opId(withdraw) == opId(withdraw)
    check opId(withdraw) != opId(WithdrawMessage(
      declarationId: declarationId,
      lockedNoteId: id(utxo),
      nonce: 2'u64,
    ))

    let active = ActiveMessage(
      declarationId: declarationId,
      nonce: 1'u64,
    )
    check opId(active) == opId(active)
    check opId(active) != opId(ActiveMessage(
      declarationId: declarationId,
      nonce: 2'u64,
    ))

  test "sdp declare opId is over wire-encoded payload, not declaration_id preimage":
    let declare = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: mkProvider(1),
      lockedNoteId: id(mkUtxo(pkSeed = 1)),
      zkId: mkUtxo(pkSeed = 1).note.zkPublicKey,
    )
    let wire = encodeSdpDeclare(declare).get
    check wire[0] == encodeServiceType(ServiceType.bn)
    check opId(declare).get != declarationId(declare).get

suite "core/mantle/tx_hashing — op_id spec vectors":
  # Payload/op_id pairs from the Mantle specification's "Operation Id" table.
  test "CHANNEL_DEPOSIT payload and op_id are unchanged by the notes rework":
    let op = ChannelDepositPayload(
      channel: filledHash32(0x10),
      inputs: Inputs(noteIds: @[smallFe(0x11)]),
      metadata: toBytes("deposit-metadata"),
    )
    check encodeChannelDeposit(op).get.toHex ==
      "1010101010101010101010101010101010101010101010101010101010101010" &
      "01" &
      "1100000000000000000000000000000000000000000000000000000000000000" &
      "10000000" & "6465706f7369742d6d65746164617461"
    check opId(op).get.toHex ==
      "f14ff0aad9bc5e8e30c5d1aa3710aaa1c1cc1f47c2c256e7d9e73104cb17ccaf"

  test "CHANNEL_WITHDRAW op_id over ChannelId || Inputs":
    let op = ChannelWithdrawPayload(
      channel: filledHash32(0x12), inputs: Inputs(noteIds: @[smallFe(0x13)]))
    check encodeChannelWithdraw(op).get.toHex ==
      "1212121212121212121212121212121212121212121212121212121212121212" &
      "01" &
      "1300000000000000000000000000000000000000000000000000000000000000"
    check opId(op).get.toHex ==
      "503d0d08f9faef971864943103965d13be7159fe6e0361c8ea614c6d0431e59c"

  test "CHANNEL_TRANSFER op_id over ChannelId || Inputs || Outputs":
    let op = ChannelTransferPayload(
      channel: filledHash32(0x14),
      inputs: Inputs(noteIds: @[smallFe(0x15)]),
      outputs: Outputs(notes: @[mkNote(0x16, pkSeed = 0x17)]),
    )
    check encodeChannelTransfer(op).get.toHex ==
      "1414141414141414141414141414141414141414141414141414141414141414" &
      "01" &
      "1500000000000000000000000000000000000000000000000000000000000000" &
      "01" & "1600000000000000" &
      "1700000000000000000000000000000000000000000000000000000000000000"
    check opId(op).get.toHex ==
      "fb24c17731954e8bbe1b0dedd69e4857c8083d1689aff331ba16f3ed5883f0ce"

  test "CHANNEL_CONFIG op_id over ChannelId || Parent || KeyCount || …":
    let op = ChannelConfigPayload(
      channel: filledHash32(0x07),
      parent: default(Hash32),
      keys: @[
        Ed25519PublicKey.init(
          "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca").get,
        Ed25519PublicKey.init(
          "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618").get,
      ],
      postingTimeframe: 10,
      postingTimeout: 11,
      configurationThreshold: 12,
      transferThreshold: 13,
    )
    check encodeChannelConfig(op).get.toHex ==
      "0707070707070707070707070707070707070707070707070707070707070707" &
      "0000000000000000000000000000000000000000000000000000000000000000" &
      "0200" &
      "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca" &
      "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618" &
      "0a000000" & "0b000000" & "0c00" & "0d00"
    check opId(op).get.toHex ==
      "8bac7efe4c3ef10745c0d509ac88e2abaf1d3cda94987ed2eeb9ad71dd31d056"

  test "CHANNEL_INSCRIBE op_id over ChannelId || Inscription || Parent || Signer":
    let op = ChannelInscribePayload(
      channelId: filledHash32(0x0e),
      inscription: toBytes("hello logos"),
      parent: default(Hash32),
      signer: Ed25519PublicKey.init(
        "d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c").get,
    )
    check encodeChannelInscribe(op).get.toHex ==
      "0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e" &
      "0b000000" & "68656c6c6f206c6f676f73" &
      "0000000000000000000000000000000000000000000000000000000000000000" &
      "d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c"
    check opId(op).get.toHex ==
      "fb9af7fb1384fff51780ec8c5afbcba76449ab7603484f797df3a472e48826c1"

  test "SDP_ACTIVE op_id over DeclarationId || Nonce || ActivityMetadata":
    check opId(mkSpecActiveMessage()).toHex ==
      "c4a2a639034016f52728f34041cf95fc2c7adb8f54cf94b4361b2d0cb72ebb70"

{.pop.}
