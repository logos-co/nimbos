# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import std/[os, strutils]
import unittest2
import stew/io2
import ../logos_chain/conf

const examplePath =
  currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0] / "../config/examples/deployment-settings.example.yaml"

const incompleteFixturePath =
  currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0] / "fixtures/deployment-settings-incomplete.yaml"

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

  test "mergeDeploymentSettingsFile copies into LBNodeConf":
    var c = LBNodeConf(cmd: BNStartUpCmd.lbNode)
    c.deploymentSettingsFile = some(InputFile(examplePath))
    check mergeDeploymentSettingsFile(c).isOk
    check c.deploymentKademliaProtocol.len > 0
    check c.deploymentMempoolPubsubTopic.len > 0

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

{.pop.}
