# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  ../testutil,
  ../../logos_chain/core/[types, block_validation, local_tree],
  ../../logos_chain/chain/genesis
from ../../logos_chain/core/mantle/primitives import SlotNumber

suite "core/block_validation":
  test "validateBlockHeader accepts child block with parent in tree":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    check validateBlock(b1, tree)

  test "validateBlockHeader rejects wrong bedrock version":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
    var b1 = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    b1.header.bedrockVersion = 99'u8
    check not validateBlock(b1, tree)

  test "validateBlockHeader rejects missing parent":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      tree = newLocalTree(genesis)
    var miss: BlockId
    miss[0] = 1'u8
    let orphan = childBlock(genesis.header, miss, SlotNumber(1), [sm])
    check not validateBlock(orphan, tree)

{.pop.}
