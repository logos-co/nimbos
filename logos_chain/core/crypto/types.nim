# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Common cryptographic wire types and little-endian / length-prefixed / fixed-size
## **byte** encoders and decoders shared across Bedrock (block ids, PRNG, Ed25519
## wire, Groth16 bytes, Mantle wire, etc.).
## Spec: [Common Cryptographic Components v1.0.2](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/common-cryptographic-components.md)
## Spec: [Bedrock v1.1 — Mantle Specification v1.10.0](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md)

{.push raises: [], gcsafe.}

import
  results,
  bincode,
  libp2p/crypto/ed25519/ed25519,
  stew/[assign2, endians2, staticfor],
  ../../zk/poseidon2/hasher           # FieldElement (+ re-exported poseidon2 symbols)

export hasher

type
  Hash32* = array[32, byte]
  ## BN254 32-byte field element as returned by Poseidon2 sponge (LE); Mantle **``ZkHash``** wire.
  ZkHash* = Hash32
  Blake2bPrngSeed* = array[64, byte]
  Blake2bPrngBlock* = array[64, byte]

  ## Spec wire-sized Groth16 proof encoding:
  ## pi_a (32 bytes) || pi_b (64 bytes) || pi_c (32 bytes).
  ## This keeps only x-coordinates and is intended for transport/storage.
  ## TODO: implement/verify the exact compressed BN254 proof codec
  ## (point sign bits, infinity representation, and canonical byte order).
  CompressedGroth16Proof* = array[128, byte]
  ## Placeholder alias until zk proof encoding is finalized.
  ZkSignature* = CompressedGroth16Proof

  ZkPublicKey* = FieldElement
  ## ZK public key wire type (32-byte field element).
  Ed25519PublicKey* = EdPublicKey
  Ed25519Signature* = EdSignature

  DecodingError* = object of CatchableError

deriveBincode(EdPublicKey)
deriveBincode(EdSignature)

const
  CompressedGroth16ProofBytes* = 128
  DefaultCompressedGroth16Proof* = default(CompressedGroth16Proof)
  DefaultZkSignature* = DefaultCompressedGroth16Proof
  DefaultEd25519Signature* = default(Ed25519Signature)

let
  KDF*: FieldElement =
    # Domain separator for the zksign key-derivation primitive: literal bytes
    # "KDF" interpreted as a little-endian Fr (auto-padded to 32 bytes).
    frFromBytesLE([byte 'K', byte 'D', byte 'F']).get
  ZeroSecretKeyPublicKey*: ZkPublicKey =
    # PK derived from SK=0 via the zksign key-derivation primitive.
    # Used to right-pad caller-supplied pk lists shorter than 32 entries.
    Poseidon2Hasher.compress(KDF, default(FieldElement))

proc zkPublicKeyFromSecret*(sk: FieldElement): ZkPublicKey =
  ## Circuit-equivalent zksign key derivation: PK = Poseidon2.compress(KDF, sk).
  Poseidon2Hasher.compress(KDF, sk)

func encodeLe*[T: SomeUnsignedInt](value: T): array[sizeof(T), byte] =
  value.toBytesLE()

func encodeByte*(value: byte): byte =
  value

func encodeU32LeLenPrefixed*(data: openArray[byte]): seq[byte] =
  ## ``UINT32`` length (LE) then payload (Inscription, Metadata, …).
  doAssert data.len <= int(high(uint32)),
    "length-prefixed data exceeds UINT32 range"
  var res = @(encodeLe(uint32(data.len)))
  res.add(data)
  res

func encodeU16LeLenPrefixed*(data: openArray[byte]): seq[byte] =
  ## ``UINT16`` length (LE) then payload (e.g. single Locator).
  doAssert data.len <= int(high(uint16)),
    "length-prefixed data exceeds UINT16 range"
  var res = @(encodeLe(uint16(data.len)))
  res.add(data)
  res

func encodeGroth16*(proof: CompressedGroth16Proof): CompressedGroth16Proof =
  ## Groth16 = 128BYTE (pi_a:32 || pi_b:64 || pi_c:32) — compressed on-wire layout.
  proof

func encodeFieldElement*(value: FieldElement): array[32, byte] =
  ## FieldElement = 32BYTE (BN254 scalar, little-endian).
  value.toBytes()

func cmpNumeric*(a, b: FieldElement): int =
  ## Ascending numeric order over the canonical encodings.
  # The encoding is little-endian, so the scan starts at the high byte.
  # A byte-wise scan from the low end would order the values wrongly.
  let
    aBytes = encodeFieldElement(a)
    bBytes = encodeFieldElement(b)
  for i in countdown(31, 0):
    if aBytes[i] != bBytes[i]:
      return cmp(aBytes[i], bBytes[i])
  0

func encodeHash32*(value: Hash32): Hash32 =
  ## Hash32 = 32BYTE.
  value

func isZero*(x: Hash32): bool =
  var
    tmp {.noinit.}: uint64
    tmp2 = 0'u64
  static: doAssert sizeof(x) mod sizeof(tmp) == 0
  staticFor i, 0 ..< sizeof(x) div sizeof(tmp):
    copyMem(addr tmp, addr x[i * sizeof(tmp)], sizeof(tmp))
    tmp2 = tmp2 or tmp
  tmp2 == 0

func encodeEd25519PublicKey*(value: Ed25519PublicKey): array[32, byte] =
  ## Ed25519 public key = 32BYTE.
  var buf: array[EdPublicKeySize, byte]
  let written = toBytes(value, buf)
  doAssert written == EdPublicKeySize, "failed to encode Ed25519 public key"
  buf

func ed25519PkToFrPair*(pk: Ed25519PublicKey): (FieldElement, FieldElement) =
  ## Split a 32-byte Ed25519 public key into two 16-byte halves, each as a
  ## BN254 field element. Used wherever a public key participates in a
  ## ZK public-input vector.
  let raw = encodeEd25519PublicKey(pk)
  (
    frFromBytesLE(raw.toOpenArray(0, 15)).get,
    frFromBytesLE(raw.toOpenArray(16, 31)).get,
  )

func encodeEd25519Signature*(value: Ed25519Signature): array[64, byte] =
  ## Ed25519 signature = 64BYTE.
  var buf: array[EdSignatureSize, byte]
  let written = toBytes(value, buf)
  doAssert written == EdSignatureSize, "failed to encode Ed25519 signature"
  buf

func encodeZkSignature*(value: ZkSignature): ZkSignature =
  ## ZkSignature = Groth16 (128-byte wire).
  encodeGroth16(value)

func encodeZkPublicKey*(value: ZkPublicKey): array[32, byte] =
  ## ZkPublicKey = FieldElement (32-byte).
  encodeFieldElement(value)

func ensureRemaining*(data: openArray[byte], pos: int, need: int) {.inline, raises: [DecodingError].} =
  if pos < 0 or pos + need > data.len:
    raise newException(DecodingError, "unexpected end of encoded data")

func finishDecode*(data: openArray[byte], pos: int) {.inline, raises: [DecodingError].} =
  if pos != data.len:
    raise newException(DecodingError, "trailing bytes after decoded value")

func readLe*[T: SomeEndianInt](data: openArray[byte], pos: var int): T {.raises: [DecodingError].} =
  ensureRemaining(data, pos, sizeof(T))
  let res = fromBytesLE(T, data.toOpenArray(pos, pos + sizeof(T) - 1))
  pos += sizeof(T)
  res

func readByte*(data: openArray[byte], pos: var int): byte {.raises: [DecodingError].} =
  ensureRemaining(data, pos, 1)
  let res = data[pos]
  pos += 1
  res

func readFixed*[N: static[int]](data: openArray[byte], pos: var int): array[N, byte] {.raises: [DecodingError].} =
  ensureRemaining(data, pos, N)
  var res: array[N, byte]
  assign(res, data.toOpenArray(pos, pos + N - 1))
  pos += N
  res

func readU32LeLenPrefixed*(data: openArray[byte], pos: var int): seq[byte] {.raises: [DecodingError].} =
  let ln = readLe[uint32](data, pos)
  if ln > uint32(data.len - pos):
    raise newException(DecodingError, "u32 length-prefixed payload exceeds buffer")
  let plen = int ln
  var res: seq[byte]
  if plen > 0:
    assign(res, data.toOpenArray(pos, pos + plen - 1))
    pos += plen
  res

func readU16LeLenPrefixed*(data: openArray[byte], pos: var int): seq[byte] {.raises: [DecodingError].} =
  let ln = readLe[uint16](data, pos)
  if ln > uint16(data.len - pos):
    raise newException(DecodingError, "u16 length-prefixed payload exceeds buffer")
  let plen = int ln
  var res: seq[byte]
  if plen > 0:
    assign(res, data.toOpenArray(pos, pos + plen - 1))
    pos += plen
  res

func decodeGroth16*(data: openArray[byte]): CompressedGroth16Proof {.raises: [DecodingError].} =
  var pos = 0
  let res = readFixed[128](data, pos)
  finishDecode(data, pos)
  res

func decodeFieldElementAt*(data: openArray[byte], pos: var int): FieldElement {.raises: [DecodingError].} =
  frFromBytesLE(readFixed[32](data, pos)).valueOr:
    raise newException(DecodingError, "field element exceeds BN254 scalar modulus")

func decodeFieldElement*(data: openArray[byte]): FieldElement {.raises: [DecodingError].} =
  var pos = 0
  let res = decodeFieldElementAt(data, pos)
  finishDecode(data, pos)
  res

func decodeHash32*(data: openArray[byte]): Hash32 {.raises: [DecodingError].} =
  var pos = 0
  let res = readFixed[32](data, pos)
  finishDecode(data, pos)
  res

func decodeEd25519PublicKey*(data: openArray[byte]): Ed25519PublicKey {.raises: [DecodingError].} =
  var pos = 0
  let raw = readFixed[EdPublicKeySize](data, pos)
  finishDecode(data, pos)
  var key: Ed25519PublicKey
  if not key.init(raw):
    raise newException(DecodingError, "invalid Ed25519 public key bytes")
  key

func decodeEd25519Signature*(data: openArray[byte]): Ed25519Signature {.raises: [DecodingError].} =
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

func decodeByte*(data: openArray[byte]): byte {.raises: [DecodingError].} =
  var pos = 0
  let res = readByte(data, pos)
  finishDecode(data, pos)
  res

func decodeU32LeLenPrefixed*(data: openArray[byte]): seq[byte] {.raises: [DecodingError].} =
  var pos = 0
  let res = readU32LeLenPrefixed(data, pos)
  finishDecode(data, pos)
  res

func decodeU16LeLenPrefixed*(data: openArray[byte]): seq[byte] {.raises: [DecodingError].} =
  var pos = 0
  let res = readU16LeLenPrefixed(data, pos)
  finishDecode(data, pos)
  res

{.pop.}
