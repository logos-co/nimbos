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
    check mantleTxHash(txA) != mantleTxHash(txB)

  test "mantleTxHash is deterministic":
    let tx = MantleTx(ops: @[])
    check mantleTxHash(tx) == mantleTxHash(tx)

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
    check opId(declare) == opId(declare)
    check opId(declare) != opId(DeclarationMessage(
      serviceType: declare.serviceType,
      locators: declare.locators,
      providerId: declare.providerId,
      lockedNoteId: id(otherUtxo),
      zkId: declare.zkId,
    ))

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
      metadata: @[],
    )
    check opId(active) == opId(active)
    check opId(active) != opId(ActiveMessage(
      declarationId: declarationId,
      nonce: 2'u64,
      metadata: @[],
    ))

  test "sdp declare opId is over wire-encoded payload, not declaration_id preimage":
    let declare = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: mkProvider(1),
      lockedNoteId: id(mkUtxo(pkSeed = 1)),
      zkId: mkUtxo(pkSeed = 1).note.zkPublicKey,
    )
    let wire = encodeSdpDeclare(declare)
    check wire[0] == encodeServiceType(ServiceType.bn)
    check opId(declare) != declarationId(declare)

suite "core/mantle/tx_hashing — channel op_id spec vectors":
  # Payload/op_id pairs from the Mantle specification's "Operation Id" table.
  test "CHANNEL_DEPOSIT payload and op_id are unchanged by the notes rework":
    let op = ChannelDepositPayload(
      channel: filledHash32(0x10),
      inputs: @[smallFe(0x11)],
      metadata: toBytes("deposit-metadata"),
    )
    check encodeChannelDeposit(op).toHex ==
      "1010101010101010101010101010101010101010101010101010101010101010" &
      "01" &
      "1100000000000000000000000000000000000000000000000000000000000000" &
      "10000000" & "6465706f7369742d6d65746164617461"
    check opId(op).toHex ==
      "f14ff0aad9bc5e8e30c5d1aa3710aaa1c1cc1f47c2c256e7d9e73104cb17ccaf"

  test "CHANNEL_WITHDRAW op_id over ChannelId || Inputs":
    let op = ChannelWithdrawPayload(
      channel: filledHash32(0x12), inputs: @[smallFe(0x13)])
    check encodeChannelWithdraw(op).toHex ==
      "1212121212121212121212121212121212121212121212121212121212121212" &
      "01" &
      "1300000000000000000000000000000000000000000000000000000000000000"
    check opId(op).toHex ==
      "503d0d08f9faef971864943103965d13be7159fe6e0361c8ea614c6d0431e59c"

  test "CHANNEL_TRANSFER op_id over ChannelId || Inputs || Outputs":
    let op = ChannelTransferPayload(
      channel: filledHash32(0x14),
      inputs: @[smallFe(0x15)],
      outputs: @[mkNote(0x16, pkSeed = 0x17)],
    )
    check encodeChannelTransfer(op).toHex ==
      "1414141414141414141414141414141414141414141414141414141414141414" &
      "01" &
      "1500000000000000000000000000000000000000000000000000000000000000" &
      "01" & "1600000000000000" &
      "1700000000000000000000000000000000000000000000000000000000000000"
    check opId(op).toHex ==
      "fb24c17731954e8bbe1b0dedd69e4857c8083d1689aff331ba16f3ed5883f0ce"

{.pop.}
