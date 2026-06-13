# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Chain initialization: load deployment settings, build genesis block, seed ledger state.

{.push raises: [], gcsafe.}

import results
import ../core/types
import ../core/local_tree
import ../deployment/deployment_settings
import ./genesis

export genesis, local_tree

type
  Chain* = object
    genesisBlock*: Block
    localTree*: LocalTree

func init*(
    genesisBlock: Block, latestImmutableHeight: uint64 = 0
): Chain =
  Chain(
    genesisBlock: genesisBlock,
    localTree: newLocalTree(genesisBlock, latestImmutableHeight),
  )

func init*(settings: DeploymentSettings): Result[Chain, string] =
  let genesisBlock = createGenesisBlock(settings.cryptarchia.genesisState.signedMantleTx)
  ok(init(genesisBlock))

{.pop.}
