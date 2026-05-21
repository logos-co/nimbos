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

const
  # http://facweb.cs.depaul.edu/sjost/it212/documents/ascii-pr.htm
  PrintableAsciiChars* = {' '..'~'}

func toPrettyString*(bytes: openArray[byte]): string =
  result = strip(string.fromBytes(bytes),
                 leading = false,
                 chars = Whitespace + {'\0'})
  if not allCharsInSet(result, PrintableAsciiChars):
    result = "0x" & toHex(bytes)

{.pop.}
