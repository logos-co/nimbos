# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Chain initialization: load deployment settings, build genesis block, seed ledger state.

{.push raises: [].}

import results
import ./core/types
import ./deployment/deployment_settings
import ./chain/genesis

export genesis

type
  Chain* = object
    genesisBlock*: Block

proc init*(settings: DeploymentSettings): Result[Chain, string] =
  ok(Chain(genesisBlock: createGenesisBlock(settings.cryptarchia.genesisState)))

{.pop.}
