# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import std/macros,
       results, stew/byteutils, presto/route,
       ../spec/eth2_apis/[rest_types, eth2_rest_serialization, rest_common],
       ../logos_chain_node,
       "."/rest_constants

## NOTE: The `rest_types` / `eth2_rest_serialization` / `rest_common` imports
## mirror the upstream Eth2 REST API type definitions, but the Logos-specific
## REST surface (paths, query parameters, and payloads) is not specified in any
## Nomos research/spec document. The concrete REST behavior in this module is
## instead aligned with the existing `logos-blockchain` implementation:
## https://github.com/logos-blockchain/logos-blockchain

export
  results, eth2_rest_serialization, rest_types,
  rest_constants, rest_common, route, decodeString

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
  ZkPublicKey* = ZkHash
  ZkHash* = array[32, byte] #TODO Replace with Fr type

func decodeLogosDigest(value: string): Result[LogosDigest, cstring] =
  try:
    var res: LogosDigest
    hexToByteArrayStrict(value, res)
    ok(Result[LogosDigest, cstring], res)
  except ValueError:
    err("Invalid hex string for LogosDigest")

func decodeString*(t: typedesc[LogosDigest], value: string): Result[LogosDigest, cstring] =
  decodeLogosDigest(value)
