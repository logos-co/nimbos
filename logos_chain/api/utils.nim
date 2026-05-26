# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import std/macros,
       results, stew/byteutils, presto/route,
       ./[types, serialization, common, constants],
       ../core/crypto/types as crypto_types

## NOTE: The `types` / `serialization` / `common` modules mirror the upstream
## Eth2 REST API type definitions, but the Logos-specific
## REST surface (paths, query parameters, and payloads) is not specified in any
## Logos Chain research/spec document. The concrete REST behavior in this module
## currently follows the Rust `logos-blockchain` implementation simply because
## it is the only reference; once a formal Logos REST spec exists, that spec
## should become the authoritative source instead:
## https://github.com/logos-blockchain/logos-blockchain

export
  results, serialization, types,
  constants, common, route, decodeString,
  crypto_types.ZkHash, crypto_types.ZkPublicKey

func disallowInterruptionsAux(body: NimNode) =
  for n in body:
    const because =
      "because the `state` variable may be mutated (and thus invalidated) " &
      "before the function resumes execution."

    if n.kind == nnkYieldStmt:
      macros.error "You cannot use yield in this block " & because, n

    if (n.kind in {nnkCall, nnkCommand} and
       n[0].kind in {nnkIdent, nnkSym} and
       $n[0] == "await"):
      macros.error "You cannot use await in this block " & because, n

    disallowInterruptionsAux(n)

macro disallowInterruptions(body: untyped) =
  disallowInterruptionsAux(body)

template strData*(body: ContentBody): string =
  bind fromBytes
  string.fromBytes(body.data)

const
  jsonMediaType* = MediaType.init("application/json")
  sszMediaType* = MediaType.init("application/octet-stream")
  textEventStreamMediaType* = MediaType.init("text/event-stream")

type
  LogosDigest* = array[32, byte]
  HeaderId* = LogosDigest

func decodeLogosDigest(value: string): Result[LogosDigest, cstring] =
  try:
    var res: LogosDigest
    hexToByteArrayStrict(value, res)
    ok(Result[LogosDigest, cstring], res)
  except ValueError:
    err("Invalid hex string for LogosDigest")

func decodeString*(t: typedesc[LogosDigest], value: string): Result[LogosDigest, cstring] =
  decodeLogosDigest(value)

func decodeString*(t: typedesc[ZkPublicKey], value: string): Result[ZkPublicKey, cstring] =
  var raw: array[32, byte]
  try:
    hexToByteArrayStrict(value, raw)
  except ValueError:
    return err("Invalid hex string for ZkPublicKey")
  try:
    ok(Result[ZkPublicKey, cstring], decodeZkPublicKey(raw))
  except DecodingError:
    err("Invalid ZkPublicKey bytes")
