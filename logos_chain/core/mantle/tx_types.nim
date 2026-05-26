# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle **transaction** layer: re-exports **``mantle/primitives``** and
## **``mantle/operations``**; **``Op``** (``Opcode`` + **``OpPayload``**),
## **``MantleTx``** / **``SignedMantleTx``**, and **``OpProof``**.
## Spec: [v1.4 Mantle](https://nomos-tech.notion.site/v1-4-Mantle-335261aa09df8065a38acff4b25aee82)
##
## Wire encoding/decoding: [v1.3 Mantle Transaction Encoding](https://nomos-tech.notion.site/v1-3-Mantle-Transaction-Encoding-335261aa09df8051a8a6f325aa41f6a7)

{.push raises: [], gcsafe.}

import ./[primitives, operations, proofs]
import ../crypto/types
export primitives, operations, proofs


type
  MantleTx* = object
    ops*: seq[Op]
    permanentStorageGasPrice*: TokenValue
    executionGasPrice*: TokenValue

  SignedMantleTx* = object
    tx*: MantleTx
    opProofs*: seq[OpProof]

func encodeMantleTx*(tx: MantleTx): seq[byte] =
  ## MantleTx = Ops || ExecutionGasPrice || StorageGasPrice
  var res = encodeOps(tx.ops)
  res.add(encodeLe(uint64(tx.executionGasPrice)))
  res.add(encodeLe(uint64(tx.permanentStorageGasPrice)))
  res

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
  let executionGasPrice = TokenValue(readLe[uint64](data, pos))
  let permanentStorageGasPrice = TokenValue(readLe[uint64](data, pos))
  finishDecode(data, pos)
  MantleTx(
    ops: ops,
    executionGasPrice: executionGasPrice,
    permanentStorageGasPrice: permanentStorageGasPrice,
  )

func decodeSignedMantleTx*(data: openArray[byte]): SignedMantleTx {.raises: [DecodingError].} =
  var pos = 0
  let count = readByte(data, pos)
  var ops = newSeqOfCap[Op](count)
  for _ in 0 ..< int(count):
    ops.add readOp(data, pos)
  let executionGasPrice = TokenValue(readLe[uint64](data, pos))
  let permanentStorageGasPrice = TokenValue(readLe[uint64](data, pos))
  let tx = MantleTx(
    ops: ops,
    executionGasPrice: executionGasPrice,
    permanentStorageGasPrice: permanentStorageGasPrice,
  )
  let opProofs =
    if pos < data.len:
      decodeOpsProofs(ops, data[pos .. data.high])
    else:
      @[]
  SignedMantleTx(tx: tx, opProofs: opProofs)
{.pop.}
