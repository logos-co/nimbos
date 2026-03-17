# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import std/[strutils, sequtils]

func isValidHexWithOptional0x*(value: string, nibbles: int): bool =
  ## Validate a hex-encoded string of a fixed nibble length.
  ## Accept both plain hex and a 0x-prefixed form.
  let start =
    if value.len >= 2 and value[0] == '0' and value[1] in {'x', 'X'}:
      2
    else:
      0

  let bodyLen = value.len - start
  if bodyLen != nibbles:
    return false

  allIt(toOpenArray(value, start, value.high), it in HexDigits)

{.pop.}