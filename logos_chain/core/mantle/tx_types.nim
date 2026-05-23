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

func encodeOpsProofs*(ops: openArray[Op], proofs: openArray[OpProof]): seq[byte] =
  ## OpsProofs = *OpProof
  ## 1. Length must be <= OpCount.
  ## 2. type(OpProofs[i]) == ProofFor(Op[i]) for provided proofs.
  doAssert proofs.len <= ops.len,
    "OpsProofs length must be <= OpCount"
  result = @[]
  for i in 0 ..< proofs.len:
    doAssert proofs[i].kind == expectedOpProofKindForOpcode(ops[i].opcode),
      "OpProof variant does not match corresponding Op"
    let encoded = encodeOpProof(proofs[i])
    result.add(encoded)

func encodeMantleTx*(tx: MantleTx): seq[byte] =
  ## MantleTx = Ops || ExecutionGasPrice || StorageGasPrice
  result = encodeOps(tx.ops)
  result.add(encodeLe(uint64(tx.executionGasPrice)))
  result.add(encodeLe(uint64(tx.permanentStorageGasPrice)))

func encodeSignedMantleTx*(signedTx: SignedMantleTx): seq[byte] =
  ## SignedMantleTx = MantleTx || OpsProofs
  result = encodeMantleTx(signedTx.tx)
  result.add(encodeOpsProofs(signedTx.tx.ops, signedTx.opProofs))

func decodeOpsProofs*(ops: openArray[Op], data: openArray[byte]): seq[OpProof] {.raises: [DecodingError].} =
  var pos = 0
  result = newSeqOfCap[OpProof](ops.len)
  var i = 0
  while pos < data.len:
    if i >= ops.len:
      raise newException(DecodingError, "OpsProofs length exceeds OpCount")
    let kind = expectedOpProofKindForOpcode(ops[i].opcode)
    result.add readOpProof(data, pos, kind)
    inc i
  if result.len > ops.len:
    raise newException(DecodingError, "OpsProofs length exceeds OpCount")
  finishDecode(data, pos)

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
  var proofs = newSeqOfCap[OpProof](ops.len)
  var i = 0
  while pos < data.len:
    if i >= ops.len:
      raise newException(DecodingError, "OpsProofs length exceeds OpCount")
    let kind = expectedOpProofKindForOpcode(ops[i].opcode)
    proofs.add readOpProof(data, pos, kind)
    inc i
  if proofs.len > ops.len:
    raise newException(DecodingError, "OpsProofs length exceeds OpCount")
  finishDecode(data, pos)
  SignedMantleTx(tx: tx, opProofs: proofs)
{.pop.}
