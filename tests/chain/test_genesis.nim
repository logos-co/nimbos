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
    check:
      h.bodyRoot == body_root([], [validGenesisTx])
      b.txs.len == 1
      b.header.bedrockVersion == GenesisBedrockVersion
      b.txs[0].tx.ops.len == validGenesisTx.tx.ops.len
      b.signature == DefaultEd25519Signature

  test "createGenesisBlock builds expected header/envelope from deployment settings":
    let
      ds = devnetDeploymentSettings
      gstate = ds.cryptarchia.genesisState
      genesisTx = gstate.validGenesisTx
      testChain = Chain.init(ds).valueOr:
        fail "Chain.init: " & $error
      gb = testChain.genesisBlock

    check:
      gb.txs.len == 1
      gb.txs[0].opProofs.len == genesisTx.opProofs.len
    for i in 0 ..< genesisTx.opProofs.len:
      check gb.txs[0].opProofs[i].kind == genesisTx.opProofs[i].kind
    check:
      gb.txs[0].tx.ops.len == genesisTx.tx.ops.len
      gb.header.bedrockVersion == GenesisBedrockVersion
      gb.header.parentBlock == default(BlockId)
      gb.header.slot == 0'u64
      gb.header.bodyRoot == body_root([], gb.txs)
      gb.header == gstate.header
      gb.signature == gstate.blockSignature

  test "createGenesisBlock from validGenesisTx matches deployment genesisState envelope":
    let
      gstate = devnetDeploymentSettings.cryptarchia.genesisState
      validGenesisTx = gstate.validGenesisTx
      fromTx = createGenesisBlock(validGenesisTx)
      fromState = initBlock(gstate.header, gstate.blockSignature, [], [validGenesisTx.hashed])

    check:
      fromTx.header == fromState.header
      blockId(fromTx.header) == blockId(fromState.header)
      fromTx.signature == fromState.signature
      fromTx.txs.len == fromState.txs.len
      fromTx.txs.len == 1
      fromTx.txs[0].hash == validGenesisTx.hash
      fromTx.txs[0].opProofs.len == fromState.txs[0].opProofs.len
    for i in 0 ..< fromTx.txs[0].opProofs.len:
      check fromTx.txs[0].opProofs[i].kind == fromState.txs[0].opProofs[i].kind

{.pop.}
