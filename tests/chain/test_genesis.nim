# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/[os, strutils],
  results,
  stew/io2,
  ../../logos_chain/core/mantle/tx_hashing,
  ../../logos_chain/chain/chain,
  ../../logos_chain/deployment/deployment_settings,
  ../testutil

const testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
const deploymentSettingsPath = testsDir / "../../config/deployment-settings.yaml"

let devnetDeploymentSettings = block:
  let text = readAllChars(deploymentSettingsPath).expect("could not read deployment settings")
  parseDeploymentSettings(text).expect("could not parse deployment settings")

suite "chain/genesis":
  test "createGenesisBlock wraps a valid genesis mantle tx":
    let
      validGenesisTx = testValidGenesisTx()
      b = createGenesisBlock(validGenesisTx)
      h = b.header
    check h.bodyRoot == body_root([], [validGenesisTx])
    check b.txs.len == 1
    check b.header.bedrockVersion == GenesisBedrockVersion
    check b.txs[0].tx.ops.len == validGenesisTx.tx.ops.len
    check b.signature == DefaultEd25519Signature

  test "createGenesisBlock builds expected header/envelope from deployment settings":
    let
      ds = devnetDeploymentSettings
      gstate = ds.cryptarchia.genesisState
      genesisTx = gstate.validGenesisTx
      testChain = Chain.init(ds, forkChoiceRule = ForkChoiceRule.Online).valueOr:
        fail "Chain.init: " & $error
      gb = testChain.genesisBlock

    check gb.txs.len == 1
    check gb.txs[0].opProofs.len == genesisTx.opProofs.len
    for i in 0 ..< genesisTx.opProofs.len:
      check gb.txs[0].opProofs[i].kind == genesisTx.opProofs[i].kind
    check gb.txs[0].tx.ops.len == genesisTx.tx.ops.len

    check gb.header.bedrockVersion == GenesisBedrockVersion
    check gb.header.parentBlock == default(BlockId)
    check gb.header.slot == 0'u64
    check gb.header.bodyRoot == body_root([], gb.txs)
    check gb.header == gstate.header
    check gb.signature == gstate.blockSignature

  test "createGenesisBlock from validGenesisTx matches deployment genesisState envelope":
    let
      gstate = devnetDeploymentSettings.cryptarchia.genesisState
      validGenesisTx = gstate.validGenesisTx
      fromTx = createGenesisBlock(validGenesisTx)
      fromState = initBlock(gstate.header, gstate.blockSignature, [], [validGenesisTx.hashed])

    check fromTx.header == fromState.header
    check blockId(fromTx.header) == blockId(fromState.header)
    check fromTx.signature == fromState.signature
    check fromTx.txs.len == fromState.txs.len
    check fromTx.txs.len == 1
    check fromTx.txs[0].hash == validGenesisTx.hash
    check fromTx.txs[0].opProofs.len == fromState.txs[0].opProofs.len
    for i in 0 ..< fromTx.txs[0].opProofs.len:
      check fromTx.txs[0].opProofs[i].kind == fromState.txs[0].opProofs[i].kind

{.pop.}
