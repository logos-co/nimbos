# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# This file contains data types that are part of the spec and thus subject to
# serialization and spec updates.
#
# The spec folder in general contains code that has been hoisted from the
# specification and that follows the spec as closely as possible, so as to make
# it easy to keep up-to-date.
#
# TODO Careful, not nil analysis is broken / incomplete and the semantics will
#      likely change in future versions of the language:
#      https://github.com/nim-lang/RFCs/issues/250
{.experimental: "notnil".}

import
  std/[macros, sets, strutils],
  results,
  chronicles,
  json_serialization,
  ssz_serialization/types as sszTypes,
  eth/common/addresses as eth

from eth/common/eth_types_json_serialization import readValue, writeValue
from stew/byteutils import fromBytes, toHex

export
  json_serialization, sszTypes, eth,
  eth_types_json_serialization.readValue,
  eth_types_json_serialization.writeValue

type
  AttestationData* = object
    index*: uint64

template newClone*[T: not ref](x: T): ref T =
  # TODO not nil in return type: https://github.com/nim-lang/Nim/issues/14146
  # TODO use only when x is a function call that returns a new instance!
  let res = new typeof(x) # TODO safe to do noinit here?
  res[] = x
  res

# TODO Careful, not nil analysis is broken / incomplete and the semantics will
#      likely change in future versions of the language:
#      https://github.com/nim-lang/RFCs/issues/250
template newClone*[T](x: ref T not nil): ref T =
  newClone(x[])

template lenu64*(x: untyped): untyped =
  uint64(len(x))

const
  # http://facweb.cs.depaul.edu/sjost/it212/documents/ascii-pr.htm
  PrintableAsciiChars = {' '..'~'}

func toPrettyString*(bytes: openArray[byte]): string =
  result = strip(string.fromBytes(bytes),
                 leading = false,
                 chars = Whitespace + {'\0'})

  # TODO: Perhaps handle UTF-8 at some point
  if not allCharsInSet(result, PrintableAsciiChars):
    result = "0x" & toHex(bytes)
