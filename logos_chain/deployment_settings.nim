# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Parse cfgsync **deployment-settings** YAML via [NimYAML](https://nimyaml.org) (YAML 1.2).
## Used to drive libp2p protocol IDs and pubsub topics from deployment config.

{.push raises: [].}

import
  std/[options, strutils],
  results,
  stew/io2,
  yaml/[dom, loading]

export YamlNode, YamlNodeKind



type
  DeploymentNetworkSettings* = object
    kademliaProtocolName*: string
    identifyProtocolName*: string
    chainSyncProtocolName*: string

  DeploymentMempoolSettings* = object
    pubsubTopic*: string

  DeploymentCryptarchiaSettings* = object
    gossipsubProtocol*: string

  DeploymentSettings* = object
    network*: DeploymentNetworkSettings
    mempool*: DeploymentMempoolSettings
    cryptarchia*: DeploymentCryptarchiaSettings

proc parseDeploymentSettingsYaml*(text: string): Result[YamlNode, string] =
  try:
    var root: YamlNode
    load(text, root)
    ok(root)
  except YamlConstructionError as e:
    err("deployment-settings: " & e.msg)
  except YamlParserError as e:
    err("deployment-settings: " & e.msg)
  except IOError as e:
    err("deployment-settings: " & e.msg)
  except OSError as e:
    err("deployment-settings: " & e.msg)

func yamlGetMap*(node: YamlNode, key: string): Option[YamlNode] =
  if node.isNil or node.kind != yMapping:
    return none(YamlNode)
  try:
    some(node[key])
  except KeyError:
    none(YamlNode)

func yamlPathScalar(root: YamlNode, keys: openArray[string]): Option[string] =
  var cur = root
  for i, k in keys:
    if cur.isNil or cur.kind != yMapping:
      return none(string)
    var nxt: YamlNode
    try:
      nxt = cur[k]
    except KeyError:
      return none(string)
    if i == keys.high:
      if nxt.kind == yScalar:
        return some(nxt.content)
      return none(string)
    if nxt.kind != yMapping:
      return none(string)
    cur = nxt
  none(string)

proc deploymentSettingsFromYaml*(root: YamlNode): Result[DeploymentSettings, string] =
  var ds: DeploymentSettings
  let nk = yamlPathScalar(root, ["network", "kademlia_protocol_name"])
  let ni = yamlPathScalar(root, ["network", "identify_protocol_name"])
  let nc = yamlPathScalar(root, ["network", "chain_sync_protocol_name"])
  let mp = yamlPathScalar(root, ["mempool", "pubsub_topic"])
  let cg = yamlPathScalar(root, ["cryptarchia", "gossipsub_protocol"])
  if nk.isNone or ni.isNone or nc.isNone or mp.isNone or cg.isNone:
    return err(
      "deployment-settings: missing network.*, mempool.pubsub_topic, or cryptarchia.gossipsub_protocol")
  ds.network.kademliaProtocolName = nk.get
  ds.network.identifyProtocolName = ni.get
  ds.network.chainSyncProtocolName = nc.get
  ds.mempool.pubsubTopic = mp.get
  ds.cryptarchia.gossipsubProtocol = cg.get
  ok(ds)

proc parseDeploymentSettings*(text: string): Result[DeploymentSettings, string] =
  let root = ? parseDeploymentSettingsYaml(text)
  if root.kind != yMapping:
    return err("deployment-settings: expected top-level mapping")
  deploymentSettingsFromYaml(root)

proc validateDeploymentSettings*(ds: DeploymentSettings): Result[void, string] =
  template need(cond: bool, msg: string) =
    if not cond:
      return err(msg)
  need(ds.network.kademliaProtocolName.len > 0, "empty network.kademlia_protocol_name")
  need(ds.network.identifyProtocolName.len > 0, "empty network.identify_protocol_name")
  need(ds.network.chainSyncProtocolName.len > 0, "empty network.chain_sync_protocol_name")
  need(ds.mempool.pubsubTopic.len > 0, "empty mempool.pubsub_topic")
  need(ds.cryptarchia.gossipsubProtocol.len > 0, "empty cryptarchia.gossipsub_protocol")
  need(ds.network.kademliaProtocolName.startsWith("/"), "network.kademlia_protocol_name must start with '/'")
  need(ds.network.identifyProtocolName.startsWith("/"), "network.identify_protocol_name must start with '/'")
  need(ds.network.chainSyncProtocolName.startsWith("/"),
    "network.chain_sync_protocol_name must start with '/'")
  need(ds.mempool.pubsubTopic.startsWith("/"), "mempool.pubsub_topic must start with '/'")
  need(ds.cryptarchia.gossipsubProtocol.startsWith("/"), "cryptarchia.gossipsub_protocol must start with '/'")
  ok()

proc mergeDeploymentSettingsFile*[T](config: var T): Result[void, string] =
  ## Generic over ``config`` so this module does not import ``conf`` (would be circular with ``conf`` importing us).
  if config.deploymentSettingsFile.isNone():
    return ok()
  let path = string(config.deploymentSettingsFile.get())
  let textRes = readAllChars(path)
  if textRes.isErr():
    return err("deployment-settings: cannot read " & path & ": " & ioErrorMsg(textRes.error))
  let text = textRes.get()
  let ds = ? parseDeploymentSettings(text)
  ? validateDeploymentSettings(ds)
  config.deploymentKademliaProtocol = ds.network.kademliaProtocolName
  config.deploymentIdentifyProtocol = ds.network.identifyProtocolName
  config.deploymentChainSyncProtocol = ds.network.chainSyncProtocolName
  config.deploymentMempoolPubsubTopic = ds.mempool.pubsubTopic
  config.deploymentCryptarchiaGossipsubProtocol = ds.cryptarchia.gossipsubProtocol
  ok()

{.pop.}
