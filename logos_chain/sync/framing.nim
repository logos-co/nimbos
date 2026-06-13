# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  bincode,
  chronicles,
  chronos,
  results,
  libp2p/stream/connection,
  stew/[assign2, endians2]

logScope:
  topics = "cryptarchia_ibd"

const CryptarchiaSyncInnerLengthPrefixSize = 4

func addPrefixLengthToPayload*(inner: seq[byte]): seq[byte] {.raises: [BincodeError].} =
  let n = inner.len.uint64
  if n > uint64(uint32.high):
    raise newException(BincodeError, "cryptarchia sync LP inner length exceeds uint32")
  let le = inner.len.uint32.toBytesLE
  var framed = newSeq[byte](CryptarchiaSyncInnerLengthPrefixSize + inner.len)
  assign(framed.toOpenArray(0, 3), le)
  if inner.len > 0:
    assign(framed.toOpenArray(4, framed.high), inner.toOpenArray(0, inner.high))
  framed

proc readCryptarchiaPrefixedInner*(
    conn: Connection
): Future[Opt[seq[byte]]] {.async: (raises: [CancelledError]).} =
  ## Read LE ``uint32`` inner length, then exactly ``innerLen`` bytes.
  try:
    var lenPrefix = newSeqUninit[byte](CryptarchiaSyncInnerLengthPrefixSize)
    await conn.readExactly(addr lenPrefix[0], CryptarchiaSyncInnerLengthPrefixSize)
    let innerLen = int(uint32.fromBytesLE(lenPrefix.toOpenArray(
        0, CryptarchiaSyncInnerLengthPrefixSize - 1)))
    if innerLen == 0:
      Opt.some(newSeq[byte]())
    else:
      var inner = newSeqUninit[byte](innerLen)
      await conn.readExactly(addr inner[0], innerLen)
      debug "IBD wire read ok", innerBytes = inner.len
      Opt.some(inner)
  except BincodeError as exc:
    debug "IBD wire read failed", exc = exc.msg
    Opt.none(seq[byte])
  except LPStreamError as exc:
    debug "IBD wire read failed", exc = exc.msg
    Opt.none(seq[byte])

proc writeCryptarchiaPrefixedInner*(
    conn: Connection, inner: seq[byte]
) {.async: (raises: [BincodeError, LPStreamError, CancelledError]).} =
  ## Prepend LE ``uint32`` inner length, then write the inner payload on the stream.
  if inner.len.uint64 > uint64(uint32.high):
    raise newException(BincodeError, "cryptarchia sync LP inner length exceeds uint32")
  let lenPrefix = inner.len.uint32.toBytesLE
  var prefix = newSeqUninit[byte](CryptarchiaSyncInnerLengthPrefixSize)
  assign(prefix.toOpenArray(0, 3), lenPrefix)
  debug "IBD wire write", innerBytes = inner.len, framedBytes = CryptarchiaSyncInnerLengthPrefixSize + inner.len
  await conn.write(prefix)
  if inner.len > 0:
    await conn.write(inner)
  debug "IBD wire write ok", framedBytes = CryptarchiaSyncInnerLengthPrefixSize + inner.len

{.pop.}
