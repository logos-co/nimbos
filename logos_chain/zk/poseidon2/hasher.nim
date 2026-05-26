# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import std/options
import results

import poseidon2
import poseidon2/[types,permutation]       # F, zero, one, HorizenLabsNew 
import constantine/math/arithmetic

type Poseidon2Hasher* = object
  s0, s1, s2: F

func init*(_: type Poseidon2Hasher): Poseidon2Hasher =
  Poseidon2Hasher(s0: zero, s1: zero, s2: zero)

func updateOne(h: var Poseidon2Hasher, x: F) =
  h.s0 += x
  permInPlace(h.s0, h.s1, h.s2, which = HorizenLabsNew)

# SAFE (Sponge API for Field Elements) padding: absorb a domain-separating
# `one` after the input so distinct-length inputs cannot collide.
func update*(h: var Poseidon2Hasher, xs: openArray[F]) =
  for x in xs:
    h.updateOne(x)
  h.updateOne(one)

func finalize*(h: Poseidon2Hasher): F =
  h.s0

func digest*(_: type Poseidon2Hasher, xs: openArray[F]): F =
  var h = Poseidon2Hasher.init()
  h.update(xs)
  h.finalize()

# Merkle compress — no SAFE padding
func compress*(_: type Poseidon2Hasher, a, b: F): F =
  var h = Poseidon2Hasher.init()
  h.s0 += a
  h.s1 += b
  permInPlace(h.s0, h.s1, h.s2, which = HorizenLabsNew)
  h.s0

# bytes → single F, little-endian (caller must ensure input fits in 254 bits)
func frFromBytesLE*(bytes: openArray[byte]): Opt[F] =
  doAssert bytes.len <= 32, "input exceeds 32 bytes"
  var padded: array[32, byte]
  for i, b in bytes:
    padded[i] = b     # LE, zero-padded to 32
  let parsed = F.fromBytes(padded)
  if parsed.isNone:
    Opt.none(F)
  else:
    Opt.some(parsed.get())

{.pop.}
