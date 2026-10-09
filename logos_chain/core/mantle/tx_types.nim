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
  bincode,
  ./[primitives, operations, proofs],
  ../crypto/types

export primitives, operations, proofs

type
  MantleTx* = object
    ops*: seq[Op]

  SignedMantleTx* = object
    tx*: MantleTx
    opProofs*: seq[OpProof]

  HashedSignedMantleTx* = object
    signedTx*: SignedMantleTx
    hash*: Hash32
    ## A ``SignedMantleTx`` paired with its precalculated ``Hash32``.
    ## Has not necessarily passed stateless or stateful validation.

  ValidSignedMantleTx* = distinct HashedSignedMantleTx
    ## A ``SignedMantleTx`` that has successfully passed all stateless structural
    ## and cryptographic verifications via ``validateMantleTxStateless``.

  ValidGenesisMantleTx* = distinct ValidSignedMantleTx
    ## A ``ValidSignedMantleTx`` that passed every stateless genesis check in
    ## ``validateGenesisTxStateless``; only state checks remain.

  AnyHashedSignedMantleTx* =
    HashedSignedMantleTx | ValidSignedMantleTx | ValidGenesisMantleTx

  AnySignedMantleTx* =
    SignedMantleTx | AnyHashedSignedMantleTx

template signedTx(t: SignedMantleTx): untyped = t
template signedTx(t: HashedSignedMantleTx): untyped = t.signedTx
template signedTx*(t: ValidSignedMantleTx): untyped = HashedSignedMantleTx(t).signedTx
template signedTx(t: ValidGenesisMantleTx): untyped = HashedSignedMantleTx(ValidSignedMantleTx(t)).signedTx

template tx*(t: AnySignedMantleTx): untyped = signedTx(t).tx
template opProofs*(t: AnySignedMantleTx): untyped = signedTx(t).opProofs

template hash*(t: ValidSignedMantleTx): untyped = HashedSignedMantleTx(t).hash
template hash*(t: ValidGenesisMantleTx): untyped = ValidSignedMantleTx(t).hash

func encodeMantleTx*(tx: MantleTx): Result[seq[byte], EncodingError] =
  ## MantleTx = OpCount (u8) || *Op
  encodeOps(tx.ops)

func encodeSignedMantleTx*[T: AnySignedMantleTx](signedTx: T): Result[seq[byte], EncodingError] =
  ## SignedMantleTx = MantleTx || OpsProofs
  when T is SignedMantleTx:
    var res = ?encodeMantleTx(signedTx.tx)
    let proofsBytes = ?encodeOpsProofs(signedTx.tx.ops, signedTx.opProofs)
    res.add(proofsBytes)
    ok(res)
  else:
    encodeSignedMantleTx(signedTx.signedTx)

func byteLen*(tx: MantleTx): int =
  ## Exact wire byte length of a MantleTx without allocating buffers.
  byteLen(tx.ops)

func byteLen*[T: AnySignedMantleTx](tx: T): int =
  ## Exact wire byte length of any signed MantleTx variant without allocating buffers.
  when T is SignedMantleTx:
    byteLen(tx.tx) + byteLen(tx.opProofs)
  else:
    byteLen(tx.signedTx)

func readMantleTx*(data: openArray[byte], pos: var int): Result[MantleTx, DecodingError] =
  let count = ?readByte(data, pos)
  var ops = newSeqOfCap[Op](count)
  for _ in 0 ..< int(count):
    ops.add ?readOp(data, pos)
  ok(MantleTx(ops: ops))

func decodeSignedMantleTx*(data: openArray[byte]): Result[SignedMantleTx, DecodingError] =
  var pos = 0
  let tx = ?readMantleTx(data, pos)
  let opProofs =
    if tx.ops.len == 0:
      ?finishDecode(data, pos)
      @[]
    elif pos < data.len:
      ?decodeOpsProofs(tx.ops, data.toOpenArray(pos, data.high))
    else:
      return err(DecodingError.MissingProofs)
  ok(SignedMantleTx(tx: tx, opProofs: opProofs))

func bincodeEncodeSignedMantleTx(tx: SignedMantleTx): seq[byte] {.raises: [BincodeError].} =
  let res = encodeSignedMantleTx(tx)
  if res.isErr:
    raise newException(BincodeError, "SignedMantleTx encoding failed: " & $res.error)
  res.get

func bincodeDecodeSignedMantleTx(data: openArray[byte]): SignedMantleTx {.raises: [BincodeError].} =
  let res = decodeSignedMantleTx(data)
  if res.isErr:
    raise newException(BincodeError, "SignedMantleTx decoding failed: " & $res.error)
  res.get

deriveBincodeCustom(
  SignedMantleTx, bincodeEncodeSignedMantleTx, bincodeDecodeSignedMantleTx, BincodeError
)

{.pop.}
