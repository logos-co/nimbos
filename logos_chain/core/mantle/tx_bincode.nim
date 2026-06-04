# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Nim-bincode serializers for ``SignedMantleTx`` that encode with Mantle
## ``encodeSignedMantleTx`` (length-prefixed blob in the outer vector, identical
## framing to nested ``seq[seq[byte]]`` on sync wire).

{.push raises: [], gcsafe.}

import faststreams
import bincode
from ../crypto/types import DecodingError
from ./tx_types import SignedMantleTx, encodeSignedMantleTx, decodeSignedMantleTx

proc serializeSignedMantleTx*(
    stream: OutputStreamHandle, value: SignedMantleTx,
    config: BincodeConfig = standard(),
) {.raises: [BincodeError, IOError].} =
  serialize(stream, encodeSignedMantleTx(value), config)

func deserializeSignedMantleTxAt*(
    data: openArray[byte], config: BincodeConfig = standard(),
    start: int = 0,
): (SignedMantleTx, int) {.raises: [BincodeError].} =
  let (payload, nbytes) = decodePrefixedByteSeq(data, config, start)
  try:
    (decodeSignedMantleTx(payload), nbytes)
  except DecodingError as e:
    raise newException(BincodeError, e.msg)

func deserializeSignedMantleTx*(
    data: openArray[byte], config: BincodeConfig = standard()
): SignedMantleTx {.raises: [BincodeError].} =
  let (value, used) = deserializeSignedMantleTxAt(data, config, 0)
  if used != data.len:
    raise newException(BincodeError, "Trailing bytes after SignedMantleTx")
  value

proc serializeSignedMantleTxToSeq*(
    value: SignedMantleTx, config: BincodeConfig = standard()
): seq[byte] {.raises: [BincodeError, IOError].} =
  var stream = memoryOutput()
  serializeSignedMantleTx(stream, value, config)
  stream.getOutput()

{.pop.}
