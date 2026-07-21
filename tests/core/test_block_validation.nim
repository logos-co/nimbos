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
  ../../logos_chain/core/[types, block_validation],
  ../../logos_chain/chain/genesis
from ../../logos_chain/core/mantle/primitives import SlotNumber

suite "core/block_validation":
  test "accepts a structurally valid block":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    check validateBlock(b1)

  test "rejects wrong bedrock version":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.header.bedrockVersion = 99'u8
    check not validateBlock(b1)

  test "rejects a block root that disagrees with the transactions":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.header.blockRoot[0] = b1.header.blockRoot[0] xor 0xff'u8
    check not validateBlock(b1)

{.pop.}
