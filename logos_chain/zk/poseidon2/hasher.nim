# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import std/options
import results

import poseidon2                            # F, zero, one, toBytes, fromBytes, +, *, == (re-exported)
import poseidon2/permutation               # HorizenLabsNew, permInPlace
import constantine/math/arithmetic

export poseidon2

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

# SAFE (Sponge API for Field Elements) padding: absorb a domain-separating
# `one` after the input so distinct-length inputs cannot collide.
func update*(h: var Poseidon2Hasher, xs: openArray[FieldElement]) =
  for x in xs:
    h.updateOne(x)
  h.updateOne(one)

func finalize*(h: Poseidon2Hasher): FieldElement =
  h.s0

func digest*(_: type Poseidon2Hasher, xs: openArray[FieldElement]): FieldElement =
  var h = Poseidon2Hasher.init()
  h.update(xs)
  h.finalize()

# Merkle compress — no SAFE padding
func compress*(_: type Poseidon2Hasher, a, b: FieldElement): FieldElement =
  var h = Poseidon2Hasher.init()
  h.s0 += a
  h.s1 += b
  permInPlace(h.s0, h.s1, h.s2, which = HorizenLabsNew)
  h.s0

# bytes → single FieldElement, little-endian (caller must ensure input fits in 254 bits)
func frFromBytesLE*(bytes: openArray[byte]): Option[FieldElement] =
  doAssert bytes.len <= 32, "input exceeds 32 bytes"
  var padded: array[32, byte]
  for i, b in bytes:
    padded[i] = b     # LE, zero-padded to 32
  FieldElement.fromBytes(padded)

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
    low = FieldElement.fromBytes(lowBytes)
    high = frFromBytesLE([bytes[31]]).get
    twoToThe248 = FieldElement.fromBytes(TwoToThe248LEBytes).get
  low + high * twoToThe248

{.pop.}
