# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Layer L0 — generic helpers usable from any layer.
# Pure utilities only: no I/O, async, DB, or network.

import std/strutils
from stew/byteutils import fromBytes, toHex

template newClone*[T: not ref](x: T): ref T =
  let res = new typeof(x)
  res[] = x
  res

template newClone*[T](x: ref T): ref T =
  newClone(x[])

template lenu64*(x: untyped): untyped =
  uint64(len(x))

type NonNegativeRatio* = object
  ## Exact rational for consensus parameters (`f`, `beta`). Derived integers
  ## use `num`/`den` arithmetic directly — no float ever materialises.
  num*, den*: uint64

const
  # http://facweb.cs.depaul.edu/sjost/it212/documents/ascii-pr.htm
  PrintableAsciiChars* = {' '..'~'}

func toPrettyString*(bytes: openArray[byte]): string =
  let pretty = strip(string.fromBytes(bytes),
                     leading = false,
                     chars = Whitespace + {'\0'})
  if not allCharsInSet(pretty, PrintableAsciiChars):
    "0x" & toHex(bytes)
  else:
    pretty

# `std/unicode.validateUtf8` accepts overlong 3- and 4-byte forms, UTF-16
# surrogates and code points above U+10FFFF, so it cannot gate wire data.
func isUtf8*(s: openArray[byte]): bool =
  ## Strict UTF-8: no overlong form, no surrogate, nothing above U+10FFFF.
  var i = 0
  while i < s.len:
    let
      lead = s[i]
      n =
        if lead < 0x80: 0
        elif lead in 0xC2'u8 .. 0xDF'u8: 1
        elif lead in 0xE0'u8 .. 0xEF'u8: 2
        elif lead in 0xF0'u8 .. 0xF4'u8: 3
        else: -1
    if n < 0 or i + n >= s.len:
      return false
    if n > 0:
      # The second byte's range is narrower after the leads that would
      # otherwise admit overlong forms, surrogates or code points too large.
      let (lo, hi) =
        case lead
        of 0xE0: (0xA0'u8, 0xBF'u8)
        of 0xED: (0x80'u8, 0x9F'u8)
        of 0xF0: (0x90'u8, 0xBF'u8)
        of 0xF4: (0x80'u8, 0x8F'u8)
        else: (0x80'u8, 0xBF'u8)
      if s[i + 1] < lo or s[i + 1] > hi:
        return false
      for j in 2 .. n:
        if s[i + j] notin 0x80'u8 .. 0xBF'u8:
          return false
    i += n + 1
  true

{.pop.}
