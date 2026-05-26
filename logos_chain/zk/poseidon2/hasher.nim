# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import results

import
  poseidon2/[types, io, permutation],   # F, zero, one, +, *, ==, fromBytes, toBytes, permInPlace
  constantine/math/arithmetic

export types, io, results

type
  FieldElement* = F
    ## BN254 scalar field element (Poseidon2 **``F``**).

  Poseidon2Hasher* = object
    s0, s1, s2: FieldElement

func init*(_: type Poseidon2Hasher): Poseidon2Hasher =
  Poseidon2Hasher(s0: zero, s1: zero, s2: zero)

func updateOne(h: var Poseidon2Hasher, x: FieldElement) =
  h.s0 += x
  permInPlace(h.s0, h.s1, h.s2, which = HorizenLabsNew)

func update*(h: var Poseidon2Hasher, xs: openArray[FieldElement]) =
  ## SAFE (Sponge API for Field Elements) padding: absorb a domain-separating
  ## `one` after the input so distinct-length inputs cannot collide.
  for x in xs:
    h.updateOne(x)
  h.updateOne(one)

func finalize*(h: Poseidon2Hasher): FieldElement =
  h.s0

func digest*(_: type Poseidon2Hasher, xs: openArray[FieldElement]): FieldElement =
  var h = Poseidon2Hasher.init()
  h.update(xs)
  h.finalize()


func compress*(_: type Poseidon2Hasher, a, b: FieldElement): FieldElement =
  # Merkle compress — no SAFE padding
  var h = Poseidon2Hasher.init()
  h.s0 += a
  h.s1 += b
  permInPlace(h.s0, h.s1, h.s2, which = HorizenLabsNew)
  h.s0

# bytes → single FieldElement, little-endian (caller must ensure input fits in 254 bits)
func frFromBytesLE*(bytes: openArray[byte]): Opt[FieldElement] =
  doAssert bytes.len <= 32, "input exceeds 32 bytes"
  var padded: array[32, byte]
  for i, b in bytes:
    padded[i] = b     # LE, zero-padded to 32
  let parsed = FieldElement.fromBytes(padded)
  if parsed.isNone:
    Opt.none(FieldElement)
  else:
    Opt.some(parsed.get())

const TwoToThe248LEBytes: array[32, byte] =
  [0u8, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 1]

func frFromBytesLEModOrder*(bytes: array[32, byte]): FieldElement =
  ## Reduce a 32-byte LE value mod field order. Used to ingest classic
  ## 32-byte digests (e.g. Blake2b output) that may exceed the BN254 modulus.
  ## Splits the input as ``low(31 bytes) + high(byte 31) * 2^248`` — both pieces
  ## are < modulus so the conversion can't fail; field arithmetic reduces.
  var lowBytes: array[31, byte]
  for i in 0 .. 30:
    lowBytes[i] = bytes[i]
  let
    low = frFromBytesLE(lowBytes).get
    high = frFromBytesLE([bytes[31]]).get
    twoToThe248 = frFromBytesLE(TwoToThe248LEBytes).get
  low + high * twoToThe248

{.pop.}
