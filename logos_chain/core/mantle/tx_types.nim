# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle **transaction** layer: re-exports **``mantle/primitives``** and
## **``mantle/operations``**; **``Op``** (``Opcode`` + **``OpPayload``**),
## **``MantleTx``** / **``SignedMantleTx``**, and **``OpProof``**.
## Spec: [Bedrock v1.1 — Mantle Specification v1.10.0](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md)

{.push raises: [], gcsafe.}

import
  ./[primitives, operations, proofs],
  ../crypto/types

export primitives, operations, proofs


type
  MantleTx* = object
    ops*: seq[Op]

  SignedMantleTx* = object
    tx*: MantleTx
    opProofs*: seq[OpProof]

  ValidSignedMantleTx* = distinct SignedMantleTx
    ## A ``SignedMantleTx`` that has successfully passed all stateless structural
    ## and cryptographic verifications via ``validateMantleTxStateless``.

template tx*(t: ValidSignedMantleTx): untyped = SignedMantleTx(t).tx
template opProofs*(t: ValidSignedMantleTx): untyped = SignedMantleTx(t).opProofs

func encodeMantleTx*(tx: MantleTx): seq[byte] =
  ## MantleTx = OpCount (u8) || *Op
  encodeOps(tx.ops)

func encodeSignedMantleTx*(signedTx: SignedMantleTx): seq[byte] =
  ## SignedMantleTx = MantleTx || OpsProofs
  var res = encodeMantleTx(signedTx.tx)
  res.add(encodeOpsProofs(signedTx.tx.ops, signedTx.opProofs))
  res

template encodeSignedMantleTx*(signedTx: ValidSignedMantleTx): seq[byte] =
  encodeSignedMantleTx(SignedMantleTx(signedTx))

func byteLen*(tx: MantleTx): int =
  ## Exact wire byte length of a MantleTx without allocating buffers.
  byteLen(tx.ops)

func byteLen*(signedTx: SignedMantleTx): int =
  ## Exact wire byte length of a SignedMantleTx without allocating buffers.
  byteLen(signedTx.tx) + byteLen(signedTx.opProofs)

template byteLen*(signedTx: ValidSignedMantleTx): int =
  byteLen(SignedMantleTx(signedTx))

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
