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
  ../../../logos_chain/core/crypto/types,
  ../../../logos_chain/core/mantle/tx_types

suite "core/mantle/tx_types":
  test "decodeMantleTx roundtrips encodeMantleTx":
    let tx = MantleTx(ops: @[])
    let wire = encodeMantleTx(tx)
    let back = decodeMantleTx(wire)
    check back.ops.len == tx.ops.len
    check wire.len == 1
    check wire[0] == byte(0)

  test "decodeSignedMantleTx roundtrips encodeSignedMantleTx":
    let signed = SignedMantleTx(
      tx: MantleTx(
        ops: @[
          createTransferOp(TransferPayload(
            inputs: Inputs(noteIds: @[]),
            outputs: Outputs(notes: @[]),
          )),
        ],
      ),
      opProofs: @[
        OpProof(kind: opfTransfer, transferProof: DefaultZkSignature),
      ],
    )
    let
      wire = encodeSignedMantleTx(signed)
      back = decodeSignedMantleTx(wire)
    check back.tx.ops.len == signed.tx.ops.len
    check back.opProofs.len == signed.opProofs.len
    check back.opProofs[0].kind == signed.opProofs[0].kind

{.pop.}
