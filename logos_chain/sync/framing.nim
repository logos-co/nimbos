# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import bincode
import stew/endians2

const CryptarchiaSyncInnerLengthPrefixSize* = 4

proc addPrefixLengthToPayload*(inner: seq[byte]): seq[byte] {.raises: [BincodeError].} =
  let n = inner.len.uint64
  if n > uint64(uint32.high):
    raise newException(BincodeError, "cryptarchia sync LP inner length exceeds uint32")
  let le = inner.len.uint32.toBytesLE
  var framed = newSeq[byte](4 + inner.len)
  copyMem(framed[0].unsafeAddr, le[0].unsafeAddr, 4)
  if inner.len > 0:
    copyMem(framed[4].unsafeAddr, inner[0].unsafeAddr, inner.len)
  framed

proc removePrefixLengthFromPacket*(frame: seq[byte]): seq[byte] {.raises: [BincodeError].} =
  if frame.len < 4:
    raise newException(BincodeError, "cryptarchia sync LP frame too short for length prefix")
  let ln = uint32.fromBytesLE(frame.toOpenArray(0, 3)).uint64
  let expected = ln + 4'u64
  if expected != frame.len.uint64:
    raise newException(BincodeError, "cryptarchia sync LP frame length mismatch")
  if ln > uint64(int.high):
    raise newException(BincodeError, "cryptarchia sync LP payload too large")
  let plen = int ln
  if plen > 0:
    var payload = newSeq[byte](plen)
    copyMem(payload[0].unsafeAddr, frame[4].unsafeAddr, plen)
    payload
  else:
    @[]

{.pop.}
