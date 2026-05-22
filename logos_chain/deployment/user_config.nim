# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[options, strutils],
  results,
  stew/io2,
  yaml/dom,
  ./helpers

export dom

const initialPeersPath* = ["network", "backend", "initial_peers"]

proc parseUserConfigYaml*(text: string): Result[YamlNode, string] =
  let root = ? parseDeploymentSettingsYaml(text)
  if root.kind != yMapping:
    return err("user-config: expected top-level mapping")
  ok(root)

proc initialPeersFromYaml*(root: YamlNode): Result[seq[string], string] =
  let node = yamlGetPathNode(root, initialPeersPath)
  if node.isNone:
    return ok(newSeq[string]())
  let peersNode = node.get
  if peersNode.kind != ySequence:
    return err("user-config: network.backend.initial_peers must be a sequence")
  var peers: seq[string]
  for i in 0 ..< peersNode.len:
    let item = peersNode[i]
    if item.kind != yScalar:
      return err("user-config: network.backend.initial_peers[" & $i & "] must be a string")
    let peerAddr = item.content.strip()
    if peerAddr.len > 0:
      peers.add(peerAddr)
  ok(peers)

proc loadUserConfigInitialPeers*(path: string): Result[seq[string], string] =
  let text = readAllChars(path).valueOr:
    return err("user-config: cannot read " & path & ": " & ioErrorMsg(error))
  let root = ? parseUserConfigYaml(text)
  initialPeersFromYaml(root)

{.pop.}
