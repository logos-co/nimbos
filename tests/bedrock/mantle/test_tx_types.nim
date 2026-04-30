# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import unittest2
import ../../../logos_chain/bedrock/mantle/tx_types
import ../../../logos_chain/bedrock/mantle/tx_hashing

suite "bedrock/mantle/tx_types":
  test "mantleTxHash is deterministic for same MantleTx":
    let tx = MantleTx(
      ops: @[],
      executionGasPrice: 0'u64,
      permanentStorageGasPrice: 0'u64,
    )
    check mantleTxHash(tx) == mantleTxHash(tx)

{.pop.}
