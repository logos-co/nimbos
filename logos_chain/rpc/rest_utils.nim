# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import std/macros,
       results, stew/byteutils, presto/route,
       ../bedrock/crypto/hashing,
       ../spec/eth2_apis/[rest_types, eth2_rest_serialization, rest_common],
       ../logos_chain_node,
       "."/rest_constants

## NOTE: The `rest_types` / `eth2_rest_serialization` / `rest_common` imports
## mirror the upstream Eth2 REST API type definitions, but the Logos-specific
## REST surface (paths, query parameters, and payloads) is not specified in any
## Logos Chain research/spec document. The concrete REST behavior in this module
## currently follows the Rust `logos-blockchain` implementation simply because
## it is the only reference; once a formal Logos REST spec exists, that spec
## should become the authoritative source instead:
## https://github.com/logos-blockchain/logos-blockchain

export
  results, eth2_rest_serialization, rest_types,
  rest_constants, rest_common, route, decodeString, Hash32

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
  ## Bedrock 32-byte hash (``array[32, byte]``); not **``hashes.Hash32``** (preimage type).
  Hash32* = hashing.Hash32
  HeaderId* = Hash32

func decodeHash32FromHex(value: string): Result[Hash32, cstring] =
  try:
    var res: Hash32
    hexToByteArrayStrict(value, res)
    ok(Result[Hash32, cstring], res)
  except ValueError:
    err("Invalid hex string for Hash32")

func decodeString*(t: typedesc[Hash32], value: string): Result[Hash32, cstring] =
  decodeHash32FromHex(value)
