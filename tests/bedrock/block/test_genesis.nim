# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import std/[os, strutils]
import unittest2
import stew/io2
import ../../../logos_chain/bedrock/mantle/tx_types
import "../../../logos_chain/bedrock/block/genesis"
import "../../../logos_chain/deployment/deployment_settings"

const testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
const deploymentSettingsPath = testsDir / "../../../config/deployment-settings.yaml"

suite "bedrock/block/genesis":
  test "createGenesisBlock wraps a minimal signed mantle tx":
    let tx = MantleTx(
      ops: @[],
      executionGasPrice: 0'u64,
      permanentStorageGasPrice: 0'u64,
    )
    let sm = SignedMantleTx(tx: tx, opProofs: @[])
    let h = createGenesisBlock(sm).header
    let b = createGenesisBlock(sm)
    check h.blockRoot == createBlockRoot([sm])
    check b.txs.len == 1
    check b.header.bedrockVersion == GenesisBedrockVersion
    check b.txs[0].tx.executionGasPrice == sm.tx.executionGasPrice
    check b.txs[0].tx.ops.len == sm.tx.ops.len

  test "createGenesisBlock builds expected header/envelope from deployment settings":
    let text = readAllChars(deploymentSettingsPath).valueOr:
      check false
      return
    let ds = parseDeploymentSettings(text).valueOr:
      check false
      return
    check validateDeploymentSettings(ds).isOk

    let genesisTx = ds.cryptarchia.genesisState
    let gb = createGenesisBlock(genesisTx)

    ## Block envelope
    check gb.txs.len == 1
    check gb.txs[0].tx.executionGasPrice == genesisTx.tx.executionGasPrice
    check gb.txs[0].tx.permanentStorageGasPrice == genesisTx.tx.permanentStorageGasPrice
    check gb.txs[0].opProofs.len == genesisTx.opProofs.len
    for i in 0 ..< genesisTx.opProofs.len:
      check gb.txs[0].opProofs[i].kind == genesisTx.opProofs[i].kind
    check gb.txs[0].tx.ops.len == genesisTx.tx.ops.len

    ## Header core fields
    check gb.header.bedrockVersion == GenesisBedrockVersion
    check gb.header.parentBlock == default(BlockId)
    check gb.header.slot == 0'u64
    check gb.header.blockRoot == createBlockRoot([genesisTx])

    ## Stubbed genesis PoL fields
    check gb.header.proofOfLeadership.leaderVoucher == default(RewardVoucher)
    check gb.header.proofOfLeadership.entropyContribution == default(ZkHash)
    check gb.header.proofOfLeadership.proof == default(ProofOfLeadershipProof)
    check gb.header.proofOfLeadership.leaderKey == default(Ed25519PublicKey)

{.pop.}
