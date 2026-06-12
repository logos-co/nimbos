# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import std/[os, strutils]
import unittest2
import stew/io2
import ../../logos_chain/core/mantle/[tx_types, tx_hashing]
import ../../logos_chain/chain/chain
import ../../logos_chain/deployment/deployment_settings

const testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
const deploymentSettingsPath = testsDir / "../../config/deployment-settings.yaml"

suite "chain/genesis":
  test "createGenesisBlock wraps a minimal signed mantle tx":
    let tx = MantleTx(ops: @[])
    let sm = SignedMantleTx(tx: tx, opProofs: @[])
    let h = createGenesisBlock(sm).header
    let b = createGenesisBlock(sm)
    check h.blockRoot == createBlockRoot([sm])
    check b.txs.len == 1
    check b.header.bedrockVersion == GenesisBedrockVersion
    check b.txs[0].tx.ops.len == sm.tx.ops.len
    check b.signature == DefaultEd25519Signature

  test "createGenesisBlock builds expected header/envelope from deployment settings":
    let text = readAllChars(deploymentSettingsPath).valueOr:
      check false
      return
    let ds = parseDeploymentSettings(text).valueOr:
      check false
      return
    check validateDeploymentSettings(ds).isOk

    let gstate = ds.cryptarchia.genesisState
    let genesisTx = gstate.signedMantleTx
    let chain = init(ds).valueOr:
      check false
      return
    let gb = chain.genesisBlock

    check gb.txs.len == 1
    check gb.txs[0].opProofs.len == genesisTx.opProofs.len
    for i in 0 ..< genesisTx.opProofs.len:
      check gb.txs[0].opProofs[i].kind == genesisTx.opProofs[i].kind
    check gb.txs[0].tx.ops.len == genesisTx.tx.ops.len

    check gb.header.bedrockVersion == GenesisBedrockVersion
    check gb.header.parentBlock == default(BlockId)
    check gb.header.slot == 0'u64
    check gb.header.blockRoot == createBlockRoot([genesisTx])
    check gb.header == gstate.header
    check gb.signature == gstate.blockSignature

  test "createGenesisBlock from genesisState matches createGenesisBlock from signedMantleTx":
    let text = readAllChars(deploymentSettingsPath).valueOr:
      check false
      return
    let ds = parseDeploymentSettings(text).valueOr:
      check false
      return
    check validateDeploymentSettings(ds).isOk

    let gstate = ds.cryptarchia.genesisState
    let byState = createGenesisBlock(gstate.signedMantleTx)
    let byTx = createGenesisBlock(gstate.signedMantleTx)

    check byState.header == byTx.header
    check blockId(byState.header) == blockId(byTx.header)
    check byState.txs.len == byTx.txs.len
    check byState.txs.len == 1
    check mantleTxHash(byState.txs[0].tx) == mantleTxHash(byTx.txs[0].tx)
    check byState.txs[0].opProofs.len == byTx.txs[0].opProofs.len
    for i in 0 ..< byState.txs[0].opProofs.len:
      check byState.txs[0].opProofs[i].kind == byTx.txs[0].opProofs[i].kind

{.pop.}
