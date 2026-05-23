# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [].}
{.used.}

import unittest2
import ../../../logos_chain/core/mantle/primitives
import ../../../logos_chain/core/mantle/tx_encoding
import ../../../logos_chain/core/mantle/tx_decoding
import ../../../logos_chain/core/mantle/tx_types

suite "core/mantle/tx_decoding":
  test "decodeValue roundtrips encodeValue":
    let v: Value = 0xAABB_CCDD_EEFF_0011'u64
    let wire = @(encodeValue(v))
    check decodeValue(wire) == v

  test "decodeMetadata roundtrips encodeMetadata":
    let m: Metadata = @[1'u8, 2'u8, 3'u8]
    let wire = encodeMetadata(m)
    check decodeMetadata(wire) == m

  test "decodeOpcode roundtrips encodeOpcode":
    let wire = @[encodeOpcode(0x42'u8)]
    check decodeOpcode(wire) == 0x42'u8

  test "decodeOpsProofs roundtrips encodeOpsProofs":
    let ops = @[
      createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[]),
      )),
      createSdpActiveOp(SdpActivePayload(
        declarationId: default(DeclarationId),
        nonce: default(Nonce),
        metadata: @[],
      )),
    ]
    let proofs = @[
      OpProof(kind: opfTransfer, transferProof: default(ZkSigProof)),
    ]
    let wire = encodeOpsProofs(ops, proofs)
    let back = decodeOpsProofs(ops, wire)
    check back.len == proofs.len
    check back[0].kind == proofs[0].kind

  test "decodeOps roundtrips encodeOps":
    let ops = @[
      createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[]),
      )),
    ]
    let wire = encodeOps(ops)
    let back = decodeOps(wire)
    check back.len == 1
    check back[0].opcode == OpTransfer
    check back[0].payload.kind == Transfer

  test "decodeChannelDeposit and decodeChannelWithdraw roundtrip encoders":
    let depPayload = ChannelDepositPayload(
      channel: default(ChannelId),
      inputs: @[default(NoteId)],
      metadata: @[],
    )
    let depWire = encodeChannelDeposit(depPayload)
    let depBack = decodeChannelDeposit(depWire)
    check depBack.channel == depPayload.channel
    check depBack.inputs == depPayload.inputs
    check depBack.metadata == depPayload.metadata

    let wdrPayload = ChannelWithdrawPayload(
      channel: default(ChannelId),
      outputs: @[],
      opIdNonce: 1'u32,
    )
    let wdrWire = encodeChannelWithdraw(wdrPayload)
    let wdrBack = decodeChannelWithdraw(wdrWire)
    check wdrBack.channel == wdrPayload.channel
    check wdrBack.outputs == wdrPayload.outputs
    check wdrBack.opIdNonce == wdrPayload.opIdNonce

  test "decodeMantleTx roundtrips encodeMantleTx":
    let tx = MantleTx(
      ops: @[],
      executionGasPrice: 7'u64,
      permanentStorageGasPrice: 8'u64,
    )
    let wire = encodeMantleTx(tx)
    let back = decodeMantleTx(wire)
    check back.ops.len == tx.ops.len

  test "decodeSignedMantleTx roundtrips encodeSignedMantleTx":
    let signed = SignedMantleTx(
      tx: MantleTx(
        ops: @[
          createTransferOp(TransferPayload(
            inputs: Inputs(noteIds: @[]),
            outputs: Outputs(notes: @[]),
          )),
        ],
        executionGasPrice: 1'u64,
        permanentStorageGasPrice: 2'u64,
      ),
      opProofs: @[
        OpProof(kind: opfTransfer, transferProof: default(ZkSigProof)),
      ],
    )
    let wire = encodeSignedMantleTx(signed)
    let back = decodeSignedMantleTx(wire)
    check back.tx.ops.len == signed.tx.ops.len
    check back.opProofs.len == signed.opProofs.len
    check back.opProofs[0].kind == signed.opProofs[0].kind

{.pop.}
