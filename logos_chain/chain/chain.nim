# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Chain initialization: load deployment settings, build genesis block, seed ledger state.

{.push raises: [], gcsafe.}

import
  results,
  ../core/[types, local_tree],
  ../deployment/deployment_settings,
  ../ledger/ledger,
  ./genesis

export genesis, local_tree

type
  Chain* = object
    genesisBlock*: Block
    localTree*: LocalTree
    ledger*: Ledger[BlockId]

func init*(T: type Chain, genesisBlock: Block, ledger: Ledger[BlockId], latestImmutableHeight: uint64 = 0): T =
  T(
    genesisBlock: genesisBlock,
    localTree: newLocalTree(genesisBlock, latestImmutableHeight),
    ledger: ledger,
  )

proc init*(T: type Chain, settings: DeploymentSettings): Result[T, string] =
  let genesisBlock = createGenesisBlock(settings.cryptarchia.genesisState.signedMantleTx)
  let sdp = SdpRegistry.init(settings.cryptarchia.sdpConfig)
  let genesisState = LedgerState.fromGenesis(sdp, genesisBlock.txs).valueOr:
    return err("chain: failed to apply genesis block: " & $error)
  let ledger = Ledger[BlockId].init(blockId(genesisBlock.header), genesisState)
  ok(T.init(genesisBlock, ledger))

{.pop.}
