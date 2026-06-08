# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import results
import bincode
import ../../testutil

import ../../../logos_chain/sync/[framing, types]

suite "sync/framing":
  test "addPrefixLengthToPayload / removePrefixLengthFromPacket roundtrips inner for download LP bodies":
    let msg = DownloadBlocksResponse(kind: dbrNoMoreBlocks)
    var inner = try:
      serializeDownloadBlocksResponseToSeq(msg, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    var lpWrap: seq[byte] = @[]
    try:
      lpWrap = addPrefixLengthToPayload(inner)
    except BincodeError as exc:
      fail exc.msg
    check lpWrap.len > 4
    let backInner =
      try:
        removePrefixLengthFromPacket(lpWrap)
      except BincodeError as exc:
        fail exc.msg
    check inner == backInner
    let dec =
      try:
        Opt.some(deserializeDownloadBlocksResponse(backInner, cryptarchiaSyncBincodeConfig))
      except BincodeError as exc:
        fail exc.msg
    check dec.isSome and dec.get.kind == msg.kind

{.pop.}
