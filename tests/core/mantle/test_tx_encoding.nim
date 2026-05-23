# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import unittest2
import ../../../logos_chain/core/mantle/primitives
import ../../../logos_chain/core/mantle/tx_encoding
import ../../../logos_chain/core/mantle/tx_hashing
import ../../../logos_chain/core/mantle/tx_types

suite "core/mantle/tx_encoding":
  test "encodeValue is uint64 LE gas scalars":
    let v: Value = 0xAABB_CCDD_EEFF_0011'u64
    let b = encodeValue(v)
    check b[0] == 0x11'u8
    check b[7] == 0xAA'u8

  test "encodeMetadata empty is length 0 u32 le":
    let m: Metadata = @[]
    let s = encodeMetadata(m)
    check s.len == 4
    check s[0] == 0'u8
    check s[1] == 0'u8
    check s[2] == 0'u8
    check s[3] == 0'u8

  test "encodeOpcode is single byte":
    check encodeOpcode(0x42'u8) == 0x42'u8

  test "encodeOpsProofs accepts proofs length <= op count":
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
    let encoded = encodeOpsProofs(ops, proofs)
    check encoded.len == 128

  test "encodeOps prefixes op count and includes opcode":
    let ops = @[
      createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[]),
      )),
    ]
    let encoded = encodeOps(ops)
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

  test "mantleTxHash is sensitive to tx bytes":
    let txA = MantleTx(
      ops: @[
        createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[]),
        )),
      ],
      executionGasPrice: 0'u64,
      permanentStorageGasPrice: 0'u64,
    )
    let txB = MantleTx(ops: @[])
    check mantleTxHash(txA) != mantleTxHash(txB)

  test "mantleTxHash is deterministic":
    let tx = MantleTx(
      ops: @[],
      executionGasPrice: 7'u64,
      permanentStorageGasPrice: 8'u64,
    )
    check mantleTxHash(tx) == mantleTxHash(tx)

{.pop.}
