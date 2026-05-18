# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [].}
{.used.}

import std/options
import unittest2

import "../../../logos_chain/sync"/[config, types]

suite "sync/config":
  test "addPrefixLengthToPayload / removePrefixLengthFromPacket roundtrips inner for download LP bodies":
    let msg = DownloadBlocksResponse(kind: dbrNoMoreBlocks)
    var inner = try:
      serializeDownloadBlocksResponseToSeq(msg, cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    var lpWrap: seq[byte] = @[]
    try:
      lpWrap = addPrefixLengthToPayload(inner)
    except CatchableError:
      discard
    check lpWrap.len > 4
    let backInner =
      try:
        removePrefixLengthFromPacket(lpWrap)
      except CatchableError:
        @[]
    check inner == backInner
    let dec =
      try:
        some(deserializeDownloadBlocksResponse(backInner, cryptarchiaSyncBincodeConfig))
      except CatchableError:
        none(DownloadBlocksResponse)
    check dec.isSome and dec.get.kind == msg.kind

{.pop.}
