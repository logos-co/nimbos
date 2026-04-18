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
import ../logos_chain/conf

const testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]

const examplePath = testsDir / "../config/examples/deployment-settings.example.yaml"

const incompleteFixturePath = testsDir / "fixtures/deployment-settings-incomplete.yaml"

const malformedFixturePath = testsDir / "fixtures/deployment-settings-malformed.yaml"

const emptyScalarsFixturePath = testsDir / "fixtures/deployment-settings-empty-scalars.yaml"

const noLeadingSlashFixturePath = testsDir / "fixtures/deployment-settings-no-leading-slash.yaml"

const wrongTypesFixturePath = testsDir / "fixtures/deployment-settings-wrong-types.yaml"

## Valid YAML with one required leaf as a sequence instead of a scalar (indices 0..4: kademlia, identify, chain_sync, mempool, cryptarchia).
const nonScalarLeafYaml: array[5, string] = [
  """
network:
  kademlia_protocol_name:
    - /a/kad
  identify_protocol_name: /a/id
  chain_sync_protocol_name: /a/sync
mempool:
  pubsub_topic: /a/mem
cryptarchia:
  gossipsub_protocol: /a/cryp
""",
  """
network:
  kademlia_protocol_name: /a/kad
  identify_protocol_name:
    - /a/id
  chain_sync_protocol_name: /a/sync
mempool:
  pubsub_topic: /a/mem
cryptarchia:
  gossipsub_protocol: /a/cryp
""",
  """
network:
  kademlia_protocol_name: /a/kad
  identify_protocol_name: /a/id
  chain_sync_protocol_name:
    - /a/sync
mempool:
  pubsub_topic: /a/mem
cryptarchia:
  gossipsub_protocol: /a/cryp
""",
  """
network:
  kademlia_protocol_name: /a/kad
  identify_protocol_name: /a/id
  chain_sync_protocol_name: /a/sync
mempool:
  pubsub_topic:
    - /a/mem
cryptarchia:
  gossipsub_protocol: /a/cryp
""",
  """
network:
  kademlia_protocol_name: /a/kad
  identify_protocol_name: /a/id
  chain_sync_protocol_name: /a/sync
mempool:
  pubsub_topic: /a/mem
cryptarchia:
  gossipsub_protocol:
    - /a/cryp
""",
]

## Minimal valid YAML for parse + validate (inline).
const minimalValidYaml = """
network:
  kademlia_protocol_name: /a/kad
  identify_protocol_name: /a/id
  chain_sync_protocol_name: /a/sync
mempool:
  pubsub_topic: /a/mem
cryptarchia:
  gossipsub_protocol: /a/cryp
"""

suite "deployment-settings":
  test "parse and validate example YAML":
    check fileExists(examplePath)
    let text = readAllChars(examplePath).valueOr:
      check false
      return
    let ds = parseDeploymentSettings(text).valueOr:
      check false
      return
    check validateDeploymentSettings(ds).isOk
    check ds.network.kademliaProtocolName.len > 0
    check ds.mempool.pubsubTopic.startsWith("/")

  test "example YAML: mantle_tx ops and ops_proofs are block sequences":
    let text = readAllChars(examplePath).valueOr:
      check false
      return
    let root = parseDeploymentSettingsYaml(text).valueOr:
      check false
      return
    let crypt = yamlGetMap(root, "cryptarchia").get()
    let gs = yamlGetMap(crypt, "genesis_state").get()
    let mt = yamlGetMap(gs, "mantle_tx").get()
    let ops = yamlGetMap(mt, "ops").get()
    check ops.kind == ySequence
    check ops.elems.len == 3
    let proofs = yamlGetMap(mt, "ops_proofs").get()
    check proofs.kind == ySequence
    check proofs.elems.len == 1

  test "mergeDeploymentSettingsFile copies into LBNodeConf":
    var c = LBNodeConf(cmd: BNStartUpCmd.lbNode)
    c.deploymentSettingsFile = some(InputFile(examplePath))
    check mergeDeploymentSettingsFile(c).isOk
    check c.deploymentKademliaProtocol.len > 0
    check c.deploymentMempoolPubsubTopic.len > 0

  test "mergeDeploymentSettingsFile skips work when path unset":
    var c = LBNodeConf(cmd: BNStartUpCmd.lbNode)
    c.deploymentSettingsFile = none(InputFile)
    check mergeDeploymentSettingsFile(c).isOk

  test "mergeDeploymentSettingsFile fails for missing file with clear message":
    let missingPath = getTempDir() / "nimbos_deployment_nonexistent_7f2a9c1e.yaml"
    var c = LBNodeConf(cmd: BNStartUpCmd.lbNode)
    c.deploymentSettingsFile = some(InputFile(missingPath))
    let r = mergeDeploymentSettingsFile(c)
    check r.isErr
    check "cannot read" in r.error
    check missingPath in r.error

  test "mergeDeploymentSettingsFile fails for incomplete YAML":
    check fileExists(incompleteFixturePath)
    var c = LBNodeConf(cmd: BNStartUpCmd.lbNode)
    c.deploymentSettingsFile = some(InputFile(incompleteFixturePath))
    let r = mergeDeploymentSettingsFile(c)
    check r.isErr
    check "deployment-settings" in r.error

  test "mergeDeploymentSettingsFile fails for malformed YAML file":
    check fileExists(malformedFixturePath)
    var c = LBNodeConf(cmd: BNStartUpCmd.lbNode)
    c.deploymentSettingsFile = some(InputFile(malformedFixturePath))
    let r = mergeDeploymentSettingsFile(c)
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
    check "missing network" in r.error

  test "parseDeploymentSettings: network not a mapping":
    check fileExists(wrongTypesFixturePath)
    let text = readAllChars(wrongTypesFixturePath).valueOr:
      check false
      return
    let r = parseDeploymentSettings(text)
    check r.isErr
    check "missing" in r.error

  test "parseDeploymentSettings: non-scalar leaf network.kademlia_protocol_name":
    let r = parseDeploymentSettings(nonScalarLeafYaml[0])
    check r.isErr
    check "missing" in r.error

  test "parseDeploymentSettings: non-scalar leaf network.identify_protocol_name":
    let r = parseDeploymentSettings(nonScalarLeafYaml[1])
    check r.isErr
    check "missing" in r.error

  test "parseDeploymentSettings: non-scalar leaf network.chain_sync_protocol_name":
    let r = parseDeploymentSettings(nonScalarLeafYaml[2])
    check r.isErr
    check "missing" in r.error

  test "parseDeploymentSettings: non-scalar leaf mempool.pubsub_topic":
    let r = parseDeploymentSettings(nonScalarLeafYaml[3])
    check r.isErr
    check "missing" in r.error

  test "parseDeploymentSettings: non-scalar leaf cryptarchia.gossipsub_protocol":
    let r = parseDeploymentSettings(nonScalarLeafYaml[4])
    check r.isErr
    check "missing" in r.error

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

  test "yamlGetMap: missing key returns none":
    let root = parseDeploymentSettingsYaml(minimalValidYaml).valueOr:
      check false
      return
    check yamlGetMap(root, "nonexistent_key").isNone

  test "yamlGetMap: non-mapping node returns none":
    let root = parseDeploymentSettingsYaml("hello").valueOr:
      check false
      return
    check yamlGetMap(root, "x").isNone

{.pop.}
