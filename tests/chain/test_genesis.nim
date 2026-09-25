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
  ../../logos_chain/core/mantle/[tx_types, tx_hashing, tx_validation],
  ../../logos_chain/chain/chain,
  ../../logos_chain/deployment/deployment_settings,
  ../testutil

const testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
const deploymentSettingsPath = testsDir / "../../config/deployment-settings.yaml"

suite "chain/genesis":
  test "createGenesisBlock wraps a minimal signed mantle tx":
    let
      validGenesisTx = testValidGenesisTx()
      vtx = ValidSignedMantleTx(validGenesisTx)
      h = createGenesisBlock(validGenesisTx).header
      b = createGenesisBlock(validGenesisTx)
    check h.bodyRoot == body_root([], [vtx])
    check b.txs.len == 1
    check b.header.bedrockVersion == GenesisBedrockVersion
    check b.txs[0].tx.ops.len == validGenesisTx.tx.ops.len
    check b.signature == DefaultEd25519Signature

  test "createGenesisBlock builds expected header/envelope from deployment settings":
    let text = readAllChars(deploymentSettingsPath).valueOr:
      fail "could not read deployment settings"
    let ds = parseDeploymentSettings(text).valueOr:
      fail "could not parse deployment settings"
    require validateDeploymentSettings(ds).isOk

    let
      gstate = ds.cryptarchia.genesisState
      genesisTx = gstate.signedMantleTx
      testChain = Chain.init(ds).valueOr:
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

  test "createGenesisBlock from signedMantleTx matches deployment genesisState envelope":
    let text = readAllChars(deploymentSettingsPath).valueOr:
      fail "could not read deployment settings"
    let ds = parseDeploymentSettings(text).valueOr:
      fail "could not parse deployment settings"
    require validateDeploymentSettings(ds).isOk

    let
      gstate = ds.cryptarchia.genesisState
      validGenesisTx = validateGenesisTxStateless(gstate.signedMantleTx).get
      fromTx = createGenesisBlock(validGenesisTx)
      fromState = initBlock(gstate.header, gstate.blockSignature, [], [gstate.signedMantleTx])

    check fromTx.header == fromState.header
    check blockId(fromTx.header) == blockId(fromState.header)
    check fromTx.signature == fromState.signature
    check fromTx.txs.len == fromState.txs.len
    check fromTx.txs.len == 1
    check fromTx.txs[0].hash == mantleTxHash(fromState.txs[0].tx).get
    check fromTx.txs[0].opProofs.len == fromState.txs[0].opProofs.len
    for i in 0 ..< fromTx.txs[0].opProofs.len:
      check fromTx.txs[0].opProofs[i].kind == fromState.txs[0].opProofs[i].kind

{.pop.}
