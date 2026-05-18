# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Block root / block id for devnet genesis (mantle tx fixture from
## ``config/deployment-settings.yaml``).

{.push raises: [].}
{.used.}

import std/[os, options, strutils]
import unittest2
import results
import stew/[byteutils, io2]
import yaml/dom
import "../../../logos_chain/deployment/deployment_settings"
import "../../../logos_chain/deployment/deployment_settings_helpers"
import "../../../logos_chain/core/block/genesis"
import "../../../logos_chain/core/block/block_types"
import "../../../logos_chain/core/mantle/tx_encoding"
import "../../../logos_chain/core/mantle/tx_hashing"

const testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
const mantleTxFixturePath = testsDir / "../../fixtures/devnet-genesis-mantle-tx.yaml"
const deploymentSettingsPath = testsDir / "../../../config/deployment-settings.yaml"
const expectedDevnetGenesisBlockId =
  "10a1b21476019f28657e8237263e9ece28fdd4e60cc3a8048d4d8b265ec13a27"
const fixedGenesisTxBytesHex =
  "0600000da0860100000000006a1aad23fe9bc27c5bce1fdb7aad5d411ee411f7e06ce30dfad620bbd4c26b270100000000000000436f14ef5343e434a3a801aab5f9ae0fcf8d73dedfb86e8fa62c04390a5ef2166400000000000000b00d63129926a40dbadd127364c057bd9af9c0c858ebaa6c146664d3e5ad492fa08601000000000090b90a71381fbab2de62a3ebc9c04c5df5f4a2bed1ef3e63e6f6f2e4d818581c010000000000000061d6d3789378ab1c9fded11088106e0e5b80314cd87998228ceb9988654e192d640000000000000068554f2143b6a9b261af872e04c927401311f7a28e2268237a5b01908e79e328a086010000000000afcd9b6ca5c015471f032a6c608d8d328d34e8fa81e10f1700bc988ed9f02c1a0100000000000000b0bf6597befcf43d29f76834c7da8c79878645692433fa77a09199358829b92c6400000000000000581361fb2ff53fb1778bb9cfcaa9e60495d2584554416efece34b2be98017f12a08601000000000040cfd3e6065a194292a581683bdd94c179f894bbbfd14cee88070beeb3d27d100100000000000000e921b702b4da5da1ff9d834f62f57e3033ff3b6d737e42a6ff9d2cb21b23ce1c6400000000000000fde99f08b1c0c78a3c379255c7ef0ada768ae365d0cef460961cb7c8c6c15518ebe3f9ffffffffff3c3a1f25710bada106a953289964ac1ed66299b85f880f2868e3d3fca99d37181100000000000000000000000000000000000000000000000000000000000000007c0000004c0000000000000070726f636573735f73746172745f6e6f6e63653d313861633632333639393066343137632d30303030303030312c20746573745f656e74726f70793d3631343438613362373963663432613143a9f869000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000010b0004416ccbeb91020d48cd03a725df50280878195d0495943915125087c2ed79e00033c216a48205977403b26da4f0e06a12be4701019ad6c4dbe408c98ed0761e66d678a5add40fdbf6bd040c2910995828e126bf7261240187c84d8b7bb289b99c9849f7afce7af1cd301a2000010b0004416ccbeb91020d49cd038f6b861560bdcca90f63bf695bfe94b24755c8b7b9997656f7a9ca27c97f6dcbfbb2a41a7a0155aeb56c803c968e41e4134871a6812f080436b2a00138a502008ff71d971082290ffdf270e1b9d616f9acd2ca792e0bc68a46a6c01d40e9142a2000010b0004416ccbeb91020d4acd033e557cad40e998678f99f93fe8cba7b13679a0bd44010851de78723729d93ba11e2f1684f4a5d1b9be3b9368eb81bf65b5988bf5ff2c97dadc02afcc50c4470c2d06650ca7fb9c5ef2485ca6788f2778029748bffb7512caab59e4a2e049d9282000010b0004416ccbeb91020d4bcd036b7278c8fe8af5d768a3d729a76b3b7ca33c25c67ed471fbe04f09f8d80539d49c9c111d4e3f7f8f734ce2e489b4c7f0581d73bc171cee91db39802f300e8e2f6d5e340340bb6f669a0b4b350d7bed7428aec44d2e9059a2f0fb51095449780000000000000000000000000000000000"
const expectedDevnetBlake2bMantleDigest =
  "611bee8e1a0563e8ab460205699ad6aad8c7b41a2a080da23ca7aa0350b12023"
const expectedDevnetGenesisBlockRoot =
  "2171571e290ec05f123842aeb111289e325e287e5bb3dbe051faf37c0cb87e20"
const expectedDevnetMantleTxHash =
  expectedDevnetGenesisBlockRoot

proc signedMantleTxFromDevnetFixture(text: string): Result[SignedMantleTx, string] =
  let yroot = ? parseDeploymentSettingsYaml(text)
  if yroot.kind != yMapping:
    return err("fixture: expected top-level mapping")
  let mantleOpt = yamlGetPathNode(yroot, ["mantle_tx"])
  let proofsOpt = yamlGetPathNode(yroot, ["ops_proofs"])
  if isNone(mantleOpt) or isNone(proofsOpt):
    return err("fixture: missing mantle_tx or ops_proofs")
  let mantle = get(mantleOpt)
  if mantle.kind != yMapping:
    return err("fixture: mantle_tx must be a mapping")
  let opsOpt = yamlGetPathNode(mantle, ["ops"])
  if isNone(opsOpt):
    return err("fixture: missing mantle_tx.ops")
  parseSignedMantleTxFromOpsYaml(
    get(opsOpt),
    get(proofsOpt),
    mantle,
    "mantle_tx.ops",
    "ops_proofs",
  )

suite "bedrock block devnet mantle_tx block root":
  test "genesis fixture single-tx block root matches deployment header.block_root":
    check fileExists(mantleTxFixturePath)
    let text = readAllChars(mantleTxFixturePath).valueOr:
      check false
      return
    let smt = signedMantleTxFromDevnetFixture(text).valueOr:
      check false
      return
    let blockRoot = createBlockRoot([smt])
    ## Must match the tx parsed from the full deployment file (fixture is a slice of that YAML).
    let dsText = readAllChars(deploymentSettingsPath).valueOr:
      check false
      return
    let ds = parseDeploymentSettings(dsText).valueOr:
      check false
      return
    let gstate = ds.cryptarchia.genesisState
    let smtFromDeployment = gstate.signedMantleTx
    ## ``MantleTx`` / ``OpProof`` contain case objects; compare via canonical tx hash.
    check mantleTxHash(smt.tx) == mantleTxHash(smtFromDeployment.tx)
    check blockRoot == createBlockRoot([smtFromDeployment])
    check toHex(blockRoot) == expectedDevnetGenesisBlockRoot
    check blockRoot == gstate.header.blockRoot
    check blockRoot == mantleTxHash(smt.tx)

  test "deployment genesis block id matches devnet header preimage":
    let dsText = readAllChars(deploymentSettingsPath).valueOr:
      check false
      return
    let ds = parseDeploymentSettings(dsText).valueOr:
      check false
      return
    check validateDeploymentSettings(ds).isOk
    let gb = createGenesisBlock(ds.cryptarchia.genesisState.signedMantleTx)
    check toHex(gb.header.blockRoot) == expectedDevnetGenesisBlockRoot
    check toHex(blockId(gb.header)) == expectedDevnetGenesisBlockId

  test "devnet genesis mantle tx encoding and hashes match fixed vectors":
    let text = readAllChars(mantleTxFixturePath).valueOr:
      check false
      return
    let smt = signedMantleTxFromDevnetFixture(text).valueOr:
      check false
      return
    let txBytes = encodeMantleTx(smt.tx)
    check toHex(txBytes) == fixedGenesisTxBytesHex
    check txBytes == hexToSeqByte(fixedGenesisTxBytesHex)
    check toHex(blake2bMantleTxDigest(txBytes)) == expectedDevnetBlake2bMantleDigest
    check toHex(mantleTxHash(smt.tx)) == expectedDevnetMantleTxHash

{.pop.}
