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
  ../../../logos_chain/core/mantle/[tx_hashing, tx_types]
suite "core/mantle/tx_hashing":
  test "mantleTxHash is sensitive to tx bytes":
    let
      txA = MantleTx(
        ops: @[
          createTransferOp(TransferPayload(
            inputs: Inputs(noteIds: @[]),
            outputs: Outputs(notes: @[]),
          )),
        ],
        executionGasPrice: 0'u64,
        permanentStorageGasPrice: 0'u64,
      )
      txB = MantleTx(ops: @[])
    check mantleTxHash(txA) != mantleTxHash(txB)

  test "mantleTxHash is deterministic":
    let tx = MantleTx(
      ops: @[],
      executionGasPrice: 7'u64,
      permanentStorageGasPrice: 8'u64,
    )
    check mantleTxHash(tx) == mantleTxHash(tx)

{.pop.}
