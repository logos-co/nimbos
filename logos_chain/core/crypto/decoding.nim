# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

## Little-endian, length-prefixed, and fixed-size **byte** decoders shared across
## Bedrock (inverse of ``crypto/encoding``).
## Spec: [v1.3 Mantle Transaction Encoding](https://nomos-tech.notion.site/v1-3-Mantle-Transaction-Encoding-335261aa09df8051a8a6f325aa41f6a7)

{.push raises: [], gcsafe.}

import std/options
import libp2p/crypto/ed25519/ed25519
import stew/endians2
import poseidon2/[types, io]
import ./hashing
import ../mantle/primitives

type
  DecodingError* = object of CatchableError

proc ensureRemaining*(data: openArray[byte], pos: int, need: int) {.inline, raises: [DecodingError].} =
  if pos < 0 or pos + need > data.len:
    raise newException(DecodingError, "unexpected end of encoded data")

proc finishDecode*(data: openArray[byte], pos: int) {.inline, raises: [DecodingError].} =
  if pos != data.len:
    raise newException(DecodingError, "trailing bytes after decoded value")

proc readLe*[T: SomeEndianInt](data: openArray[byte], pos: var int): T {.raises: [DecodingError].} =
  ensureRemaining(data, pos, sizeof(T))
  result = fromBytesLE(T, data.toOpenArray(pos, pos + sizeof(T) - 1))
  pos += sizeof(T)

proc readByte*(data: openArray[byte], pos: var int): byte {.raises: [DecodingError].} =
  ensureRemaining(data, pos, 1)
  result = data[pos]
  pos += 1

proc readFixed*[N: static[int]](data: openArray[byte], pos: var int): array[N, byte] {.
  raises: [DecodingError]
.} =
  ensureRemaining(data, pos, N)
  for i in 0 ..< N:
    result[i] = data[pos + i]
  pos += N

proc readU32LeLenPrefixed*(data: openArray[byte], pos: var int): seq[byte] {.
  raises: [DecodingError]
.} =
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

proc readU16LeLenPrefixed*(data: openArray[byte], pos: var int): seq[byte] {.
  raises: [DecodingError]
.} =
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

proc decodeGroth16*(data: openArray[byte]): array[128, byte] {.raises: [DecodingError].} =
  var pos = 0
  result = readFixed[128](data, pos)
  finishDecode(data, pos)

proc decodeFieldElementAt*(data: openArray[byte], pos: var int): F {.raises: [DecodingError].} =
  let parsed = F.fromBytes(readFixed[32](data, pos))
  if parsed.isNone:
    raise newException(DecodingError, "field element exceeds BN254 scalar modulus")
  parsed.get()

func decodeFieldElement*(data: openArray[byte]): F {.raises: [DecodingError].} =
  var pos = 0
  result = decodeFieldElementAt(data, pos)
  finishDecode(data, pos)

func decodeHash32*(data: openArray[byte]): Hash32 {.raises: [DecodingError].} =
  var pos = 0
  result = readFixed[32](data, pos)
  finishDecode(data, pos)

proc decodeEd25519PublicKey*(data: openArray[byte]): Ed25519PublicKey {.raises: [DecodingError].} =
  var pos = 0
  let raw = readFixed[EdPublicKeySize](data, pos)
  finishDecode(data, pos)
  var key: Ed25519PublicKey
  if not key.init(raw):
    raise newException(DecodingError, "invalid Ed25519 public key bytes")
  key

proc decodeEd25519Signature*(data: openArray[byte]): Ed25519Signature {.raises: [DecodingError].} =
  var pos = 0
  let raw = readFixed[EdSignatureSize](data, pos)
  finishDecode(data, pos)
  var sig: Ed25519Signature
  if not sig.init(raw):
    raise newException(DecodingError, "invalid Ed25519 signature bytes")
  sig

func decodeZkSignature*(data: openArray[byte]): ZkSignature {.raises: [DecodingError].} =
  decodeGroth16(data)

func decodeZkPublicKey*(data: openArray[byte]): ZkPublicKey {.raises: [DecodingError].} =
  decodeFieldElement(data)

proc decodeByte*(data: openArray[byte]): byte {.raises: [DecodingError].} =
  var pos = 0
  result = readByte(data, pos)
  finishDecode(data, pos)

proc decodeU32LeLenPrefixed*(data: openArray[byte]): seq[byte] {.raises: [DecodingError].} =
  var pos = 0
  result = readU32LeLenPrefixed(data, pos)
  finishDecode(data, pos)

proc decodeU16LeLenPrefixed*(data: openArray[byte]): seq[byte] {.raises: [DecodingError].} =
  var pos = 0
  result = readU16LeLenPrefixed(data, pos)
  finishDecode(data, pos)

{.pop.}
