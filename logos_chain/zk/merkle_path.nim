# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Merkle inclusion path → circuit witness encoding shared by the PoL, PoC,
## and PoQ input builders.

{.push raises: [], gcsafe.}

import
  ../core/crypto/types,
  ../utils/dynamic_merkle_tree

export FieldElement, TreeDepth, MerklePath, MerkleNode, Side

type
  CircuitPath*[N: static int] = object
    ## Inclusion path of an `N`-level tree. Siblings stay leaf → root.
    ## Selectors are emitted root → leaf and are `true` when the sibling is
    ## the left child.
    siblings*: array[N, FieldElement]
    selectors*: array[N, bool]

func toCircuitPath*(path: MerklePath): CircuitPath[TreeDepth] =
  var encoded: CircuitPath[TreeDepth]
  for i in 0 ..< TreeDepth:
    encoded.siblings[i] = path[i].sibling
    encoded.selectors[i] = path[TreeDepth - 1 - i].side == Side.Left
  encoded

{.pop.}
