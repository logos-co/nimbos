# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle **transaction** layer: re-exports **``mantle/primitives``** and
## **``mantle/operations``**; **``Op``** (``Opcode`` + **``OpPayload``**),
## **``MantleTx``** / **``SignedMantleTx``**, and **``OpProof``**.
## Spec: [v1.5.0 Mantle](https://nomos-tech.notion.site/1-5-0-Mantle-33d261aa09df8051b0d0cd4d5ddade85)
##
## Wire encoding/decoding: [v1.4.1 Mantle Transaction Encoding](https://nomos-tech.notion.site/1-4-1-Mantle-Transaction-Encoding-33e261aa09df8050beb6c9b72a042217)

{.push raises: [], gcsafe.}

import ./[primitives, operations, proofs]
import ../crypto/types
export primitives, operations, proofs


type
  MantleTx* = object
    ops*: seq[Op]

  SignedMantleTx* = object
    tx*: MantleTx
    opProofs*: seq[OpProof]

func encodeMantleTx*(tx: MantleTx): seq[byte] =
  ## MantleTx = OpCount (u8) || *Op
  encodeOps(tx.ops)

func encodeSignedMantleTx*(signedTx: SignedMantleTx): seq[byte] =
  ## SignedMantleTx = MantleTx || OpsProofs
  var res = encodeMantleTx(signedTx.tx)
  res.add(encodeOpsProofs(signedTx.tx.ops, signedTx.opProofs))
  res

func decodeMantleTx*(data: openArray[byte]): MantleTx {.raises: [DecodingError].} =
  var pos = 0
  let count = readByte(data, pos)
  var ops = newSeqOfCap[Op](count)
  for _ in 0 ..< int(count):
    ops.add readOp(data, pos)
  finishDecode(data, pos)
  MantleTx(ops: ops)

func decodeSignedMantleTx*(data: openArray[byte]): SignedMantleTx {.raises: [DecodingError].} =
  var pos = 0
  let count = readByte(data, pos)
  var ops = newSeqOfCap[Op](count)
  for _ in 0 ..< int(count):
    ops.add readOp(data, pos)
  let tx = MantleTx(ops: ops)
  let opProofs =
    if ops.len == 0:
      @[]
    elif pos < data.len:
      decodeOpsProofs(ops, data[pos .. data.high])
    else:
      raise newException(DecodingError, "SignedMantleTx: missing OpsProofs")
  SignedMantleTx(tx: tx, opProofs: opProofs)
{.pop.}
