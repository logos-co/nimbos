# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

## Little-endian, length-prefixed, and fixed-size **byte** decoders shared across
## Bedrock (inverse of ``crypto/encoding``).
## Spec: [v1.3 Mantle Transaction Encoding](https://nomos-tech.notion.site/v1-3-Mantle-Transaction-Encoding-335261aa09df8051a8a6f325aa41f6a7)

{.push raises: [DecodingError], gcsafe.}

import libp2p/crypto/ed25519/ed25519
import stew/endians2

type
  DecodingError* = object of CatchableError

proc ensureRemaining*(data: openArray[byte], pos: int, need: int) {.inline.} =
  if pos < 0 or pos + need > data.len:
    raise newException(DecodingError, "unexpected end of encoded data")

proc finishDecode*(data: openArray[byte], pos: int) {.inline.} =
  if pos != data.len:
    raise newException(DecodingError, "trailing bytes after decoded value")

proc readLe*[T: SomeEndianInt](data: openArray[byte], pos: var int): T =
  ensureRemaining(data, pos, sizeof(T))
  result = fromBytesLE(T, data.toOpenArray(pos, pos + sizeof(T) - 1))
  pos += sizeof(T)

proc readByte*(data: openArray[byte], pos: var int): byte =
  ensureRemaining(data, pos, 1)
  result = data[pos]
  pos += 1

proc readFixed*[N: static[int]](data: openArray[byte], pos: var int): array[N, byte] =
  ensureRemaining(data, pos, N)
  for i in 0 ..< N:
    result[i] = data[pos + i]
  pos += N

proc readU32LeLenPrefixed*(data: openArray[byte], pos: var int): seq[byte] =
  let ln = readLe[uint32](data, pos)
  if ln > uint32(data.len - pos):
    raise newException(DecodingError, "u32 length-prefixed payload exceeds buffer")
  let plen = int ln
  if plen > 0:
    result = newSeq[byte](plen)
    copyMem(result[0].addr, data[pos].unsafeAddr, plen)
    pos += plen
  else:
    result = @[]

proc readU16LeLenPrefixed*(data: openArray[byte], pos: var int): seq[byte] =
  let ln = readLe[uint16](data, pos)
  if ln > uint16(data.len - pos):
    raise newException(DecodingError, "u16 length-prefixed payload exceeds buffer")
  let plen = int ln
  if plen > 0:
    result = newSeq[byte](plen)
    copyMem(result[0].addr, data[pos].unsafeAddr, plen)
    pos += plen
  else:
    result = @[]

proc decodeGroth16*(data: openArray[byte]): array[128, byte] =
  var pos = 0
  result = readFixed[128](data, pos)
  finishDecode(data, pos)

proc decodeFieldElement*(data: openArray[byte]): array[32, byte] =
  var pos = 0
  result = readFixed[32](data, pos)
  finishDecode(data, pos)

proc decodeHash32*(data: openArray[byte]): array[32, byte] =
  decodeFieldElement(data)

proc decodeEd25519PublicKey*(data: openArray[byte]): EdPublicKey =
  var pos = 0
  let raw = readFixed[EdPublicKeySize](data, pos)
  finishDecode(data, pos)
  var key: EdPublicKey
  if not key.init(raw):
    raise newException(DecodingError, "invalid Ed25519 public key bytes")
  key

proc decodeEd25519Signature*(data: openArray[byte]): EdSignature =
  var pos = 0
  let raw = readFixed[EdSignatureSize](data, pos)
  finishDecode(data, pos)
  var sig: EdSignature
  if not sig.init(raw):
    raise newException(DecodingError, "invalid Ed25519 signature bytes")
  sig

proc decodeZkSignature*(data: openArray[byte]): array[128, byte] =
  decodeGroth16(data)

proc decodeZkPublicKey*(data: openArray[byte]): array[32, byte] =
  decodeFieldElement(data)

proc decodeByte*(data: openArray[byte]): byte =
  var pos = 0
  result = readByte(data, pos)
  finishDecode(data, pos)

proc decodeU32LeLenPrefixed*(data: openArray[byte]): seq[byte] =
  var pos = 0
  result = readU32LeLenPrefixed(data, pos)
  finishDecode(data, pos)

proc decodeU16LeLenPrefixed*(data: openArray[byte]): seq[byte] =
  var pos = 0
  result = readU16LeLenPrefixed(data, pos)
  finishDecode(data, pos)

{.pop.}
