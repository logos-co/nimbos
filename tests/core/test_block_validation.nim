# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [].}
{.used.}

import unittest2

import ../../logos_chain/core/types
import ../../logos_chain/chain/genesis
import ../../logos_chain/core/block_validation
import ../../logos_chain/core/mantle/tx_types
import ../../logos_chain/core/local_tree

from ../../logos_chain/core/mantle/primitives import SlotNumber

proc minimalSignedTx(): SignedMantleTx =
  SignedMantleTx(
    tx: MantleTx(
      ops: @[],
      executionGasPrice: 0'u64,
      permanentStorageGasPrice: 0'u64,
    ),
    opProofs: @[],
  )

proc childBlock(
    parentHdr: Header,
    parentId: BlockId,
    slot: SlotNumber,
    txs: openArray[SignedMantleTx],
): Block =
  let h = initHeader(
    bedrockVersion = parentHdr.bedrockVersion,
    parentBlock = parentId,
    slot = slot,
    txs = txs,
    proofOfLeadership = parentHdr.proofOfLeadership,
  )
  initBlock(h, txs)

suite "core/block_validation":
  test "validateBlockHeader accepts child block with parent in tree":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    let b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    check validateBlock(b1, tree)

  test "validateBlockHeader rejects wrong bedrock version":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    var b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    b1.header.bedrockVersion = 99'u8
    check not validateBlockHeader(b1, tree)

  test "validateBlockHeader rejects missing parent":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let tree = newLocalTree(genesis)
    var miss: BlockId
    miss[0] = 1'u8
    let orphan = childBlock(genesis.header, miss, SlotNumber(1), [sm])
    check not validateBlockHeader(orphan, tree)

{.pop.}
