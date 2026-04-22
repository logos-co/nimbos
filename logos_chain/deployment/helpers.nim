# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Internal helpers for deployment-settings YAML parsing and field extraction.

{.push raises: [].}

import
  std/[options, strutils],
  results,
  yaml/[dom, loading]

## -----------------------------------------------------------------------------
## YAML navigation helpers
## -----------------------------------------------------------------------------

func yamlGetPathNode*(root: YamlNode, keys: openArray[string]): Option[YamlNode] =
  var cur = root
  for k in keys:
    if cur.isNil or cur.kind != yMapping:
      return none(YamlNode)
    try:
      cur = cur[k]
    except KeyError:
      return none(YamlNode)
  some(cur)

func yamlGetPathScalar*(root: YamlNode, keys: openArray[string]): Option[string] =
  if keys.len == 0:
    return none(string)
  let node = yamlGetPathNode(root, keys)
  if node.isNone or node.get.kind != yScalar:
    return none(string)
  some(node.get.content)

## -----------------------------------------------------------------------------
## YAML parsing entrypoint
## -----------------------------------------------------------------------------

proc parseDeploymentSettingsYaml*(text: string): Result[YamlNode, string] =
  try:
    var root: YamlNode
    load(text, root)
    ok(root)
  except YamlConstructionError, YamlParserError, IOError, OSError:
    err("deployment-settings: " & getCurrentExceptionMsg())

## -----------------------------------------------------------------------------
## Required structure validation
## -----------------------------------------------------------------------------

func requireTopLevelMapping*(root: YamlNode, name: string): Result[void, string] =
  if root.kind != yMapping:
    return err("deployment-settings: expected top-level mapping")
  try:
    let n = root[name]
    if n.kind != yMapping:
      return err("deployment-settings: expected top-level section '" & name & "' to be a mapping")
  except KeyError:
    return err("deployment-settings: missing top-level section: " & name)
  ok()

## -----------------------------------------------------------------------------
## Typed scalar extraction
## -----------------------------------------------------------------------------

func reqScalar*(root: YamlNode, path: openArray[string]): Result[string, string] =
  let s = yamlGetPathScalar(root, path)
  if s.isNone:
    return err("deployment-settings: missing or non-scalar " & path.join("."))
  ok(s.get)

template reqParsed(
    root: YamlNode,
    path: openArray[string],
    parse: untyped,
    expectedType: string
): untyped =
  let s = ? reqScalar(root, path)
  try:
    ok(parse(s))
  except ValueError:
    err("deployment-settings: expected " & expectedType & " at " & path.join("."))

func reqInt*(root: YamlNode, path: openArray[string]): Result[int, string] =
  reqParsed(root, path, parseInt, "integer")

func reqFloat*(root: YamlNode, path: openArray[string]): Result[float, string] =
  reqParsed(root, path, parseFloat, "float")

{.pop.}
