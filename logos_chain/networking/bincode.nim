# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Dummy P2P wire serialization format for the protocol DSL backend.
# TODO remove this module and replace it with nim-bincode support for nim-serialization

import
  faststreams/[inputs, outputs],
  serialization/[errors, formats],
  stew/endians2

export errors, formats

serializationFormat Bincode

type
  BincodeReader* = object
    stream: InputStream

  BincodeWriter* = object
    stream: OutputStream

  Limit* = int64
  List*[T; maxLen: static Limit] = distinct seq[T]

Bincode.setReader BincodeReader
Bincode.setWriter BincodeWriter, PreferredOutput = seq[byte]

func asSeq*[T; N: static int](x: List[T, N]): seq[T] = distinctBase(x)

iterator items*[T; N: static int](x: List[T, N]): T =
  for item in distinctBase(x): yield item

func init*(T: type BincodeReader, stream: InputStream): T = T(stream: stream)
func init*(T: type BincodeWriter, stream: OutputStream): T = T(stream: stream)

proc readValue*[T](r: var BincodeReader, value: var T) {.raises: [SerializationError, IOError].} =
  when T is uint64:
    var buf: array[8, byte]
    if not r.stream.readInto(buf):
      raise (ref SerializationError)(msg: "Unexpected end of stream")
    value = fromBytesLE(uint64, buf)
  elif T is List:
    let n = r.stream.len.get(0)
    if n > 0:
      value = T(@(r.stream.read(n)))
  else:
    discard

proc writeValue*[T](w: var BincodeWriter, value: T) {.raises: [IOError].} =
  when T is uint64:
    w.stream.write(toBytesLE(value))
  elif T is List:
    w.stream.write(asSeq(value))
  else:
    discard
