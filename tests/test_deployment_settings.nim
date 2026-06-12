# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import std/[os, strutils]
import chronos
import unittest2
import stew/io2
import ../logos_chain/conf
import ../logos_chain/deployment/deployment_settings

const testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]

const deploymentSettingsPath = testsDir / "../config/deployment-settings.yaml"

const incompleteFixturePath = testsDir / "fixtures/deployment-settings-incomplete.yaml"

const malformedFixturePath = testsDir / "fixtures/deployment-settings-malformed.yaml"

const emptyScalarsFixturePath = testsDir / "fixtures/deployment-settings-empty-scalars.yaml"

const noLeadingSlashFixturePath = testsDir / "fixtures/deployment-settings-no-leading-slash.yaml"

const wrongTypesFixturePath = testsDir / "fixtures/deployment-settings-wrong-types.yaml"

const deploymentSettingsBlendBlock = """
blend:
  common:
    num_blend_layers: 1
    minimum_network_size: 1
    protocol_name: /stub/blend
    data_replication_factor: 0
  core:
    scheduler:
      cover:
        message_frequency_per_round: 1.0
        intervals_for_safety_buffer: 1
      delayer:
        maximum_release_delay_in_rounds: 1
    minimum_messages_coefficient: 1
    normalization_constant: 1.0
    activity_threshold_sensitivity: 1
"""

const deploymentGenesisBlockMin = """
  genesis_block:
    header:
      version: Bedrock
      parent_block: '0000000000000000000000000000000000000000000000000000000000000000'
      slot: 0
      block_root: '0000000000000000000000000000000000000000000000000000000000000000'
      proof_of_leadership:
        proof: '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        entropy_contribution: '0000000000000000000000000000000000000000000000000000000000000000'
        leader_key: '0000000000000000000000000000000000000000000000000000000000000000'
        voucher_cm: '0000000000000000000000000000000000000000000000000000000000000000'
    signature: '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    transactions:
    - mantle_tx:
        ops:
        - opcode: 0
          payload:
            inputs: []
            outputs:
            - value: 1
              pk: '0000000000000000000000000000000000000000000000000000000000000001'
        - opcode: 17
          payload:
            channel_id: '0000000000000000000000000000000000000000000000000000000000000000'
            inscription: '00'
            parent: '0000000000000000000000000000000000000000000000000000000000000000'
            signer: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
      ops_proofs:
      - !ZkSig
        pi_a: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        pi_b: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        pi_c: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
      - !Ed25519Sig '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
"""

const deploymentSettingsCryptarchiaBlock = """
cryptarchia:
  epoch_config:
    epoch_stake_distribution_stabilization: 1
    epoch_period_nonce_buffer: 1
    epoch_period_nonce_stabilization: 1
  security_param: 1
  slot_activation_coeff:
    numerator: 1
    denominator: 1
  learning_rate: 0.5
  sdp_config:
    service_params:
      BN:
        lock_period: 1
        inactivity_period: 1
        retention_period: 1
        timestamp: 0
    min_stake:
      threshold: 1
      timestamp: 0
  gossipsub_protocol: /a/cryp
""" & deploymentGenesisBlockMin & """
  faucet_pk: '0000000000000000000000000000000000000000000000000000000000000001'
"""

const deploymentSettingsTimeBlock = """
time:
  slot_duration: '1.0'
"""

## Full structural stub + one protocol leaf as a sequence instead of a scalar (indices 0..4: kademlia, identify, chain_sync, mempool, cryptarchia).
const nonScalarLeafYaml: array[5, string] = [
  deploymentSettingsBlendBlock & """
network:
  kademlia_protocol_name:
    - /a/kad
  identify_protocol_name: /a/id
  chain_sync_protocol_name: /a/sync
""" & "\n" & deploymentSettingsCryptarchiaBlock & "\n" & deploymentSettingsTimeBlock & """
mempool:
  pubsub_topic: /a/mem
""",
  deploymentSettingsBlendBlock & """
network:
  kademlia_protocol_name: /a/kad
  identify_protocol_name:
    - /a/id
  chain_sync_protocol_name: /a/sync
""" & "\n" & deploymentSettingsCryptarchiaBlock & "\n" & deploymentSettingsTimeBlock & """
mempool:
  pubsub_topic: /a/mem
""",
  deploymentSettingsBlendBlock & """
network:
  kademlia_protocol_name: /a/kad
  identify_protocol_name: /a/id
  chain_sync_protocol_name:
    - /a/sync
""" & "\n" & deploymentSettingsCryptarchiaBlock & "\n" & deploymentSettingsTimeBlock & """
mempool:
  pubsub_topic: /a/mem
""",
  deploymentSettingsBlendBlock & """
network:
  kademlia_protocol_name: /a/kad
  identify_protocol_name: /a/id
  chain_sync_protocol_name: /a/sync
""" & "\n" & deploymentSettingsCryptarchiaBlock & "\n" & deploymentSettingsTimeBlock & """
mempool:
  pubsub_topic:
    - /a/mem
""",
  deploymentSettingsBlendBlock & """
network:
  kademlia_protocol_name: /a/kad
  identify_protocol_name: /a/id
  chain_sync_protocol_name: /a/sync
""" & "\n" & """
cryptarchia:
  epoch_config:
    epoch_stake_distribution_stabilization: 1
    epoch_period_nonce_buffer: 1
    epoch_period_nonce_stabilization: 1
  security_param: 1
  slot_activation_coeff:
    numerator: 1
    denominator: 1
  learning_rate: 0.5
  sdp_config:
    service_params:
      BN:
        lock_period: 1
        inactivity_period: 1
        retention_period: 1
        timestamp: 0
    min_stake:
      threshold: 1
      timestamp: 0
  gossipsub_protocol:
    - /a/cryp
""" & deploymentGenesisBlockMin & """
  faucet_pk: '0000000000000000000000000000000000000000000000000000000000000001'
""" & deploymentSettingsTimeBlock & """
mempool:
  pubsub_topic: /a/mem
""",
]

## Minimal valid YAML for parse + validate (matches cfgsync deployment-settings shape).
const minimalValidYaml = deploymentSettingsBlendBlock & """
network:
  kademlia_protocol_name: /a/kad
  identify_protocol_name: /a/id
  chain_sync_protocol_name: /a/sync
""" & "\n" & deploymentSettingsCryptarchiaBlock & "\n" & deploymentSettingsTimeBlock & """
mempool:
  pubsub_topic: /a/mem
"""

suite "deployment-settings":
  test "parse and validate canonical deployment-settings YAML":
    check fileExists(deploymentSettingsPath)
    let text = readAllChars(deploymentSettingsPath).valueOr:
      check false
      return
    let ds = parseDeploymentSettings(text).valueOr:
      check false
      return
    check validateDeploymentSettings(ds).isOk
    check ds.network.kademliaProtocolName.len > 0
    check ds.mempool.pubsubTopic.startsWith("/")
    check ds.blend.common.numBlendLayers > 0
    check ds.cryptarchia.genesisState.signedMantleTx.tx.ops.len > 0

  test "deployment-settings: mantle_tx ops and ops_proofs are block sequences":
    let text = readAllChars(deploymentSettingsPath).valueOr:
      check false
      return
    let root = parseDeploymentSettingsYaml(text).valueOr:
      check false
      return
    let crypt = yamlGetPathNode(root, ["cryptarchia"]).get()
    let gb = yamlGetPathNode(crypt, ["genesis_block"]).get()
    let txs = yamlGetPathNode(gb, ["transactions"]).get()
    let tx0 = txs[0]
    let mt = yamlGetPathNode(tx0, ["mantle_tx"]).get()
    let ops = yamlGetPathNode(mt, ["ops"]).get()
    check ops.kind == ySequence
    check ops.elems.len == 6
    let proofs = yamlGetPathNode(tx0, ["ops_proofs"]).get()
    check proofs.kind == ySequence
    check proofs.elems.len == 6

  test "loadDeploymentSettings validates canonical YAML":
    var c = LBNodeConf(cmd: BNStartUpCmd.lbNode)
    c.deploymentSettingsFile = InputFile(deploymentSettingsPath)
    let r = loadDeploymentSettings(c.deploymentSettingsFile)
    check r.isOk
    check r.get.network.kademliaProtocolName.len > 0
    check r.get.network.identifyProtocolName.len > 0

  test "loadDeploymentSettings fails for missing file with clear message":
    let missingPath = getTempDir() / "nimbos_deployment_nonexistent_7f2a9c1e.yaml"
    var c = LBNodeConf(cmd: BNStartUpCmd.lbNode)
    c.deploymentSettingsFile = InputFile(missingPath)
    let r = loadDeploymentSettings(c.deploymentSettingsFile)
    check r.isErr
    check "cannot read" in r.error
    check missingPath in r.error

  test "loadDeploymentSettings fails for incomplete YAML":
    check fileExists(incompleteFixturePath)
    var c = LBNodeConf(cmd: BNStartUpCmd.lbNode)
    c.deploymentSettingsFile = InputFile(incompleteFixturePath)
    let r = loadDeploymentSettings(c.deploymentSettingsFile)
    check r.isErr
    check "deployment-settings" in r.error

  test "loadDeploymentSettings fails for malformed YAML file":
    check fileExists(malformedFixturePath)
    var c = LBNodeConf(cmd: BNStartUpCmd.lbNode)
    c.deploymentSettingsFile = InputFile(malformedFixturePath)
    let r = loadDeploymentSettings(c.deploymentSettingsFile)
    check r.isErr
    check "deployment-settings" in r.error

  test "parseDeploymentSettingsYaml: empty stream":
    let r = parseDeploymentSettingsYaml("")
    check r.isErr
    check "deployment-settings" in r.error

  test "parseDeploymentSettingsYaml: invalid YAML syntax":
    let r = parseDeploymentSettingsYaml("network: [\n  x")
    check r.isErr
    check "deployment-settings" in r.error

  test "parseDeploymentSettingsYaml: multiple documents rejected":
    let r = parseDeploymentSettingsYaml("---\nfoo: bar\n...\n---\nbaz: qux\n...")
    check r.isErr
    check "deployment-settings" in r.error

  test "parseDeploymentSettings: top-level must be mapping (scalar root)":
    let r = parseDeploymentSettings("plain_scalar")
    check r.isErr
    check "expected top-level mapping" in r.error

  test "parseDeploymentSettings: top-level must be mapping (sequence root)":
    let r = parseDeploymentSettings("- a\n- b")
    check r.isErr
    check "expected top-level mapping" in r.error

  test "parseDeploymentSettings: missing required paths":
    let r = parseDeploymentSettings("network:\n  kademlia_protocol_name: /x\n")
    check r.isErr
    check "missing top-level section: blend" in r.error

  test "parseDeploymentSettings: network not a mapping":
    check fileExists(wrongTypesFixturePath)
    let text = readAllChars(wrongTypesFixturePath).valueOr:
      check false
      return
    let r = parseDeploymentSettings(text)
    check r.isErr
    check "expected top-level section 'network' to be a mapping" in r.error

  test "parseDeploymentSettings: non-scalar leaf network.kademlia_protocol_name":
    let r = parseDeploymentSettings(nonScalarLeafYaml[0])
    check r.isErr
    check "missing or non-scalar" in r.error

  test "parseDeploymentSettings: non-scalar leaf network.identify_protocol_name":
    let r = parseDeploymentSettings(nonScalarLeafYaml[1])
    check r.isErr
    check "missing or non-scalar" in r.error

  test "parseDeploymentSettings: non-scalar leaf network.chain_sync_protocol_name":
    let r = parseDeploymentSettings(nonScalarLeafYaml[2])
    check r.isErr
    check "missing or non-scalar" in r.error

  test "parseDeploymentSettings: non-scalar leaf mempool.pubsub_topic":
    let r = parseDeploymentSettings(nonScalarLeafYaml[3])
    check r.isErr
    check "missing or non-scalar" in r.error

  test "parseDeploymentSettings: non-scalar leaf cryptarchia.gossipsub_protocol":
    let r = parseDeploymentSettings(nonScalarLeafYaml[4])
    check r.isErr
    check "missing or non-scalar" in r.error

  test "validateDeploymentSettings: empty kademlia string":
    check fileExists(emptyScalarsFixturePath)
    let text = readAllChars(emptyScalarsFixturePath).valueOr:
      check false
      return
    let ds = parseDeploymentSettings(text).valueOr:
      check false
      return
    let v = validateDeploymentSettings(ds)
    check v.isErr
    check "empty network.kademlia_protocol_name" in v.error

  test "validateDeploymentSettings: protocol without leading slash":
    check fileExists(noLeadingSlashFixturePath)
    let text = readAllChars(noLeadingSlashFixturePath).valueOr:
      check false
      return
    let ds = parseDeploymentSettings(text).valueOr:
      check false
      return
    let v = validateDeploymentSettings(ds)
    check v.isErr
    check "kademlia_protocol_name must start with '/'" in v.error

  test "validateDeploymentSettings: all checks pass for minimal valid":
    let ds = parseDeploymentSettings(minimalValidYaml).valueOr:
      check false
      return
    check validateDeploymentSettings(ds).isOk

  test "deploymentSettingsFromYaml: typed fields and genesis subtree on minimal valid":
    let ds = parseDeploymentSettings(minimalValidYaml).valueOr:
      check false
      return
    check ds.blend.common.protocolName == "/stub/blend"
    check ds.time.slotDuration == 1.seconds
    check ds.cryptarchia.securityParam == 1
    check ds.cryptarchia.genesisState.signedMantleTx.tx.ops.len == 2

  test "validateDeploymentSettings: empty blend.common.protocol_name":
    let badYaml = deploymentSettingsBlendBlock.replace(
        "protocol_name: /stub/blend", "protocol_name: \"\"") & """
network:
  kademlia_protocol_name: /a/kad
  identify_protocol_name: /a/id
  chain_sync_protocol_name: /a/sync
""" & "\n" & deploymentSettingsCryptarchiaBlock & "\n" & deploymentSettingsTimeBlock & """
mempool:
  pubsub_topic: /a/mem
"""
    let ds = parseDeploymentSettings(badYaml).valueOr:
      check false
      return
    let v = validateDeploymentSettings(ds)
    check v.isErr
    check "empty blend.common.protocol_name" in v.error

  test "validateDeploymentSettings: zero cryptarchia slot coeff denominator":
    let badYaml = deploymentSettingsBlendBlock & """
network:
  kademlia_protocol_name: /a/kad
  identify_protocol_name: /a/id
  chain_sync_protocol_name: /a/sync
""" & "\n" & deploymentSettingsCryptarchiaBlock.replace("denominator: 1", "denominator: 0") &
      "\n" & deploymentSettingsTimeBlock & """
mempool:
  pubsub_topic: /a/mem
"""
    let ds = parseDeploymentSettings(badYaml).valueOr:
      check false
      return
    let v = validateDeploymentSettings(ds)
    check v.isErr
    check "cryptarchia.slot_activation_coeff.denominator must be > 0" in v.error

  test "parseDeploymentSettings: empty time.slot_duration":
    let badYaml = deploymentSettingsBlendBlock & """
network:
  kademlia_protocol_name: /a/kad
  identify_protocol_name: /a/id
  chain_sync_protocol_name: /a/sync
""" & "\n" & deploymentSettingsCryptarchiaBlock & """
time:
  slot_duration: ''
mempool:
  pubsub_topic: /a/mem
"""
    let p = parseDeploymentSettings(badYaml)
    check p.isErr
    check "time.slot_duration" in p.error

  test "yamlGetMap: missing key returns none":
    let root = parseDeploymentSettingsYaml(minimalValidYaml).valueOr:
      check false
      return
    check yamlGetPathNode(root, ["nonexistent_key"]).isNone

  test "yamlGetMap: non-mapping node returns none":
    let root = parseDeploymentSettingsYaml("hello").valueOr:
      check false
      return
    check yamlGetPathNode(root, ["x"]).isNone

{.pop.}
