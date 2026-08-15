# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  stew/byteutils as byteutils,
  results,
  bincode,
  ../../testutil,
  ../../../logos_chain/sync/[framing, types]

suite "sync/framing (u32 inner length prefix)":
  test "GetTip request wire frame is u32 inner length then bincode":
    let inner = try:
      encode(RequestMessage(kind: rmGetTip), cryptarchiaSyncBincodeConfig)
    except BincodeError:
      fail getCurrentExceptionMsg()
    check inner == @[1'u8, 0'u8, 0'u8, 0'u8]
    let lpBody = try:
      addPrefixLengthToPayload(inner)
    except BincodeError as exc:
      fail exc.msg
    check byteutils.toHex(lpBody) == "0400000001000000"
    check lpBody.len == 4 + inner.len
    let m = try:
      Opt.some(decode(
        lpBody.toOpenArray(4, lpBody.high), RequestMessage, cryptarchiaSyncBincodeConfig))
    except BincodeError as exc:
      fail exc.msg
    check m.isSome and m.get.kind == rmGetTip

{.pop.}
