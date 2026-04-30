# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import unittest2
import ../../../logos_chain/bedrock/mantle/tx_types
import "../../../logos_chain/bedrock/block/genesis"

suite "bedrock/block/genesis":
  test "createGenesisHeader includes single tx in computed blockRoot":
    let tx = MantleTx(
      ops: @[],
      executionGasPrice: 0'u64,
      permanentStorageGasPrice: 0'u64,
    )
    let sm = SignedMantleTx(tx: tx, opProofs: @[])
    let h = createGenesisHeader(sm)
    check h.blockRoot == createBlockRoot([sm])

  test "createGenesisBlock wraps a single signed mantle tx":
    let tx = MantleTx(
      ops: @[],
      executionGasPrice: 0'u64,
      permanentStorageGasPrice: 0'u64,
    )
    let sm = SignedMantleTx(tx: tx, opProofs: @[])
    let b = createGenesisBlock(sm)
    check b.txs.len == 1
    check b.header.bedrockVersion == GenesisBedrockVersion
    check b.txs[0].tx.executionGasPrice == sm.tx.executionGasPrice
    check b.txs[0].tx.ops.len == sm.tx.ops.len

{.pop.}
