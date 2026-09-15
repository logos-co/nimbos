# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Merkle inclusion path → circuit witness encoding.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../../logos_chain/zk/poseidon2/hasher,
  ../../logos_chain/zk/merkle_path

suite "zk/merkle_path — circuit encoding":
  test "selectors are reversed and true when the sibling is on the left":
    # Two markers at asymmetric positions: an unreversed encoding would put
    # them at indices 0 and 5 instead of 31 and 26.
    var path: MerklePath
    for i in 0 ..< TreeDepth:
      path[i] = MerkleNode(side: Side.Right, sibling: toF(i))
    path[0].side = Side.Left      # leaf level
    path[5].side = Side.Left
    let c = toCircuitPath(path)
    for i in 0 ..< TreeDepth:
      check c.siblings[i] == toF(i)
    check c.selectors[TreeDepth - 1] == true   # leaf level ← path[0]
    check c.selectors[TreeDepth - 6] == true   # ← path[5]
    check c.selectors[0] == false
    check c.selectors[5] == false

{.pop.}
