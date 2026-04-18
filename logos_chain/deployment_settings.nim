# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Parse cfgsync **deployment-settings** YAML (subset: nested maps and string/number scalars).
## Used to drive libp2p protocol IDs and pubsub topics from deployment config.

{.push raises: [], gcsafe.}

import
  std/[options, strutils, tables],
  results

type
  YamlNodeKind* = enum
    ykScalar
    ykMap

  YamlNode* = ref YamlNodeObj
  YamlNodeObj* = object
    case kind*: YamlNodeKind
    of ykScalar:
      scalar*: string
    of ykMap:
      map*: OrderedTable[string, YamlNode]

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

func lineIndent(line: string): int =
  var n = 0
  while n < line.len and line[n] == ' ':
    inc n
  n

func stripLineComment(line: string): string =
  var inS = false
  var inD = false
  var i = 0
  while i < line.len:
    let c = line[i]
    if not inS and not inD and c == '#':
      return line[0 ..< i].strip(leading = false, trailing = true)
    if not inD and c == '\'':
      inS = not inS
    elif not inS and c == '\"':
      inD = not inD
    inc i
  line.strip(leading = false, trailing = true)

func findKeyValueSep(s: string): int =
  ## Index of separating ``:`` between YAML key and value (not inside quotes).
  var i = 0
  while i < s.len:
    let c = s[i]
    if c == '\'':
      inc i
      while i < s.len and s[i] != '\'':
        inc i
      if i < s.len:
        inc i
    elif c == '\"':
      inc i
      while i < s.len and s[i] != '\"':
        inc i
      if i < s.len:
        inc i
    elif c == ':':
      return i
    else:
      inc i
  -1

proc splitKeyValue(line: string): (string, string) =
  let sep = findKeyValueSep(line)
  if sep < 0:
    return ("", "")
  let key = line[0 ..< sep].strip()
  var value = ""
  if sep + 1 < line.len:
    value = line[sep + 1 .. ^1].strip()
  if value.len >= 2 and value[0] == value[^1] and value[0] in {'\'', '\"'}:
    value = value[1 ..< ^1]
  (key, value)

proc prepareLines(text: string): seq[string] =
  for raw in text.splitLines():
    let stripped = stripLineComment(raw)
    if stripped.len > 0:
      result.add(stripped)

proc parseYamlMap(lines: seq[string], i: var int, mapIndent: int): Result[YamlNode, string] =
  var m = initOrderedTable[string, YamlNode]()
  while i < lines.len:
    let ind = lineIndent(lines[i])
    if ind < mapIndent:
      break
    if ind > mapIndent:
      return err("deployment-settings YAML: unexpected indent at line: " & lines[i])
    let content = lines[i][ind .. ^1]
    inc i
    let (key, valueAfterColon) = splitKeyValue(content)
    if key.len == 0:
      continue
    if valueAfterColon.len > 0:
      m[key] = YamlNode(kind: ykScalar, scalar: valueAfterColon)
      continue
    var childIndent = -1
    var j = i
    while j < lines.len:
      let indJ = lineIndent(lines[j])
      if strip(lines[j]).len == 0:
        inc j
        continue
      if indJ <= ind:
        break
      childIndent = indJ
      break
    if childIndent < 0:
      m[key] = YamlNode(kind: ykScalar, scalar: "")
      continue
    let child = ? parseYamlMap(lines, i, childIndent)
    m[key] = child
  ok(YamlNode(kind: ykMap, map: m))

proc parseDeploymentSettingsYaml*(text: string): Result[YamlNode, string] =
  let lines = prepareLines(text)
  var i = 0
  parseYamlMap(lines, i, 0)

func yamlGetMap(node: YamlNode, key: string): Option[YamlNode] =
  if node.isNil or node.kind != ykMap:
    return none(YamlNode)
  let v = node.map.getOrDefault(key, nil)
  if v.isNil:
    return none(YamlNode)
  some(v)

func yamlPathScalar(root: YamlNode, keys: openArray[string]): Option[string] =
  var cur = root
  for i, k in keys:
    if cur.isNil or cur.kind != ykMap:
      return none(string)
    let nxt = yamlGetMap(cur, k).get(nil)
    if nxt.isNil:
      return none(string)
    if i == keys.high:
      if nxt.kind == ykScalar:
        return some(nxt.scalar)
      return none(string)
    if nxt.kind != ykMap:
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
  if root.kind != ykMap:
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
