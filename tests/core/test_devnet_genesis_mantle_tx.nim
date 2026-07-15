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

import
  std/[os, strutils],
  unittest2,
  results,
  stew/[byteutils, io2],
  yaml/dom,
  ../../logos_chain/deployment/[deployment_settings, deployment_settings_helpers],
  ../../logos_chain/chain/genesis,
  ../../logos_chain/core/[types, crypto/hashing],
  ../../logos_chain/core/mantle/[tx_types, tx_hashing]

const testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
const mantleTxFixturePath = testsDir / "../fixtures/devnet-genesis-mantle-tx.yaml"
const deploymentSettingsPath = testsDir / "../../config/deployment-settings.yaml"
const expectedDevnetGenesisBlockId =
  "fd234c1a01246ce66ee5d1f10184aa8be37435c2caa0dd8b8bf0318980bca973"
const fixedGenesisTxBytesHex =
  "03000005a086010000000000e3635f207984ae779cf76b5f20714b514373f61ff96260879fe0a6d71f2dce07640000000000000039e16b432574571a6bcd8ee36e370589641bd9f35367f6f97a972453c46c322564000000000000009750fa86471fddc69749aa9f8568ef6635e64d9f9aa815e8cb932cea183c8e180100000000000000852efb444db8c3c811625850df39425f43aeffc69571192c0be9f72523256e0affffffffffffffffd2a1977db29daf6691f7ce897fe7b666ec964b1bf027814cacd1a2c141b12f101100000000000000000000000000000000000000000000000000000000000000003c00000010000000000000007374616e64616c6f6e652d6c6f63616c9169fe692d2ddf918544bca603c5a291c7dd1b902d6769ff4b00021506780e075c06051a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000010b00047f00000191020d48cd03aa70aafc48536ae13168ed4845981a40cbd2dc1c38df88d04c46250e9ad65ce0852efb444db8c3c811625850df39425f43aeffc69571192c0be9f72523256e0aa4405fdbd782bd39c4e388ac470c98fdca3e9edfdf7d2672bc63223d75dab721"
const expectedDevnetBlake2bMantleDigest =
  "34cf5bf9e82e335c5ad0e1fa4411c79b9e2a80f52ebc6e595265a18ee400f23b"
const expectedDevnetGenesisBlockRoot =
  "7d3a7840601116778cda80fe20ebc0aed85018cbc7535b768c7f40168373af67"
const expectedDevnetMantleTxHash =
  expectedDevnetGenesisBlockRoot

proc signedMantleTxFromDevnetFixture(text: string): Result[SignedMantleTx, string] =
  let yroot = ? parseDeploymentSettingsYaml(text)
  if yroot.kind != yMapping:
    return err("fixture: expected top-level mapping")
  let
    mantle = yamlGetPathNode(yroot, ["mantle_tx"]).valueOr:
      return err("fixture: missing mantle_tx or ops_proofs")
    proofsNode = yamlGetPathNode(yroot, ["ops_proofs"]).valueOr:
      return err("fixture: missing mantle_tx or ops_proofs")
  if mantle.kind != yMapping:
    return err("fixture: mantle_tx must be a mapping")
  let opsNode = yamlGetPathNode(mantle, ["ops"]).valueOr:
    return err("fixture: missing mantle_tx.ops")
  parseSignedMantleTxFromOpsYaml(
    opsNode,
    proofsNode,
    "mantle_tx.ops",
    "ops_proofs",
  )

suite "devnet genesis mantle_tx block root":
  test "genesis fixture single-tx block root matches deployment header.block_root":
    check fileExists(mantleTxFixturePath)
    let
      text = readAllChars(mantleTxFixturePath).valueOr:
        check false
        return
      smt = signedMantleTxFromDevnetFixture(text).valueOr:
        check false
        return
      blockRoot = createBlockRoot([smt])
      dsText = readAllChars(deploymentSettingsPath).valueOr:
        check false
        return
      ds = parseDeploymentSettings(dsText).valueOr:
        check false
        return
      gstate = ds.cryptarchia.genesisState
      smtFromDeployment = gstate.signedMantleTx
    check mantleTxHash(smt.tx) == mantleTxHash(smtFromDeployment.tx)
    check blockRoot == createBlockRoot([smtFromDeployment])
    check toHex(blockRoot) == expectedDevnetGenesisBlockRoot
    check blockRoot == gstate.header.blockRoot
    check blockRoot == mantleTxHash(smt.tx)

  test "deployment genesis block id matches devnet header preimage":
    let
      dsText = readAllChars(deploymentSettingsPath).valueOr:
        check false
        return
      ds = parseDeploymentSettings(dsText).valueOr:
        check false
        return
    check validateDeploymentSettings(ds).isOk
    let gb = createGenesisBlock(ds.cryptarchia.genesisState.signedMantleTx)
    check toHex(gb.header.blockRoot) == expectedDevnetGenesisBlockRoot
    check toHex(blockId(gb.header)) == expectedDevnetGenesisBlockId

  test "devnet genesis mantle tx encoding and hashes match fixed vectors":
    let
      text = readAllChars(mantleTxFixturePath).valueOr:
        check false
        return
      smt = signedMantleTxFromDevnetFixture(text).valueOr:
        check false
        return
      txBytes = encodeMantleTx(smt.tx)
    check toHex(txBytes) == fixedGenesisTxBytesHex
    check txBytes == hexToSeqByte(fixedGenesisTxBytesHex)
    check toHex(blake2b256Hash(txBytes)) == expectedDevnetBlake2bMantleDigest
    check toHex(mantleTxHash(smt.tx)) == expectedDevnetMantleTxHash

{.pop.}
