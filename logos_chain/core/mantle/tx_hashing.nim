# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle transaction hashing helpers.
## Spec: [Bedrock v1.1 — Mantle Specification v1.10.0](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md)

{.push raises: [], gcsafe.}

import
  bincode,
  ./[tx_types, operations],
  ../crypto/hashing

const
  MantleTxHashDomainTag = "MANTLE_TXHASH_V1"
  OperationIdV1DomainTag = "OPERATION_ID_V1"

type
  # TODO (perf): `HashedSignedMantleTx` is defined as a `ref object` to enable zero-copy
  # 8-byte pointer sharing across mempool, block proposals, block validation, and the fork tree
  # under `--mm:refc`, avoiding recursive `genericSeqAssign` container deep-copies. However,
  # individual heap allocations per transaction may cause heap fragmentation or GC pressure under
  # sustained high TPS or large IBD batches. Optimize by introducing a block-scoped arena / slab
  # allocator (e.g. `MemRegion`), bump-allocating all transactions in a block contiguously and
  # freeing the entire arena in a single O(1) operation upon block retirement.
  HashedSignedMantleTx* = ref object
    signedTx: SignedMantleTx
    hash: Hash32
    ## A ``SignedMantleTx`` paired with its precalculated ``Hash32``.
    ## Has not necessarily passed stateless or stateful validation.

func signedTx*(htx: HashedSignedMantleTx): lent SignedMantleTx {.inline.} =
  htx.signedTx

func hash*(htx: HashedSignedMantleTx): Hash32 {.inline.} =
  htx.hash

template tx*(t: HashedSignedMantleTx): untyped = signedTx(t).tx
template opProofs*(t: HashedSignedMantleTx): untyped = signedTx(t).opProofs

func encodeSignedMantleTx*(htx: HashedSignedMantleTx): Result[seq[byte], EncodingError] {.inline.} =
  encodeSignedMantleTx(htx.signedTx)

func byteLen*(htx: HashedSignedMantleTx): int {.inline.} =
  ## Exact wire byte length of a HashedSignedMantleTx without allocating buffers.
  byteLen(htx.signedTx)

func mantleTxHash*(tx: MantleTx): Result[Hash32, EncodingError] =
  ## mantle_txhash = Blake2b-256("MANTLE_TXHASH_V1" || encode_mantle_tx(tx))
  let encoded = ?encodeMantleTx(tx)
  ok(blake2b256Hash(MantleTxHashDomainTag, encoded))

func createGenesisHtx*(
    signedTx: sink SignedMantleTx,
): Result[HashedSignedMantleTx, EncodingError] =
  ## Constructs a HashedSignedMantleTx strictly for the genesis transaction
  ## loaded from deployment settings. Transactions received from the network
  ## compute their hash from wire bytes during bincode decoding.
  ## Test fixtures should use `createHashedSignedMantleTxForTest`.
  let h = ?mantleTxHash(signedTx.tx)
  ok(HashedSignedMantleTx(signedTx: signedTx, hash: h))

# TODO (perf): Encoding currently delegates to `encodeSignedMantleTx`, which allocates and
# concatenates intermediate seq[byte] buffers. Optimize by accepting an `OutputStreamHandle`
# directly (e.g. `encode*(stream: OutputStreamHandle, htx: HashedSignedMantleTx)`), enabling
# zero-copy streaming into bincode / network output buffers.
func bincodeEncodeHashedSignedMantleTx(htx: HashedSignedMantleTx): seq[byte] {.raises: [BincodeError].} =
  if htx.isNil:
    raise newException(BincodeError, "cannot encode nil HashedSignedMantleTx")
  encodeSignedMantleTx(htx).valueOr:
    raise newException(BincodeError, "HashedSignedMantleTx encoding failed: " & $error)

func bincodeDecodeHashedSignedMantleTx*(data: openArray[byte]): HashedSignedMantleTx {.raises: [BincodeError].} =
  ## Decodes a SignedMantleTx and hashes the MantleTx wire slice in place (no re-encode).
  ## INVARIANT: data[0 ..< txWireLen] == encodeMantleTx(MantleTx(ops: ops)).
  # TODO (perf): While the outer `ops` and `opProofs` sequences are moved zero-copy
  # into HashedSignedMantleTx, per-op payloads (e.g. TransferPayload inputs/outputs) and proofs
  # undergo genericAssign/genericSeqAssign deep-copies when unwrapping Result values in `readOp`
  # and `ops.add`. Optimize via var out-parameters (in-place decoding into `ops[i]`).
  var pos = 0
  let count = readByte(data, pos).valueOr:
    raise newException(BincodeError, "HashedSignedMantleTx decoding failed: " & $error)
  var ops = newSeqOfCap[Op](count)
  for _ in 0 ..< int(count):
    let op = readOp(data, pos).valueOr:
      raise newException(BincodeError, "HashedSignedMantleTx decoding failed: " & $error)
    ops.add op
  let txWireLen = pos
  var opProofs: seq[OpProof]
  if ops.len == 0:
    finishDecode(data, pos).isOkOr:
      raise newException(BincodeError, "HashedSignedMantleTx decoding failed: " & $error)
  elif pos < data.len:
    decodeOpsProofsInto(ops, data.toOpenArray(pos, data.high), opProofs).isOkOr:
      raise newException(BincodeError, "HashedSignedMantleTx decoding failed: " & $error)
  else:
    raise newException(BincodeError, "HashedSignedMantleTx decoding failed: MissingProofs")
  let h = blake2b256Hash(MantleTxHashDomainTag, data.toOpenArray(0, txWireLen - 1))
  HashedSignedMantleTx(
    signedTx: SignedMantleTx(tx: MantleTx(ops: move(ops)), opProofs: move(opProofs)),
    hash: h,
  )

deriveBincodeCustom(
  HashedSignedMantleTx, bincodeEncodeHashedSignedMantleTx, bincodeDecodeHashedSignedMantleTx, BincodeError
)

func opId*(op: TransferPayload): Result[Hash32, EncodingError] =
  ## op_id = Blake2b-256("OPERATION_ID_V1" || encode_op_bytes(op))
  let encoded = ?encodeTransfer(op)
  ok(blake2b256Hash(OperationIdV1DomainTag, encoded))

func opId*(op: DeclarationMessage): Result[Hash32, EncodingError] =
  ## op_id = Blake2b-256("OPERATION_ID_V1" || encode_op_bytes(op))
  let encoded = ?encodeSdpDeclare(op)
  ok(blake2b256Hash(OperationIdV1DomainTag, encoded))

func opId*(op: WithdrawMessage): Hash32 =
  ## op_id = Blake2b-256("OPERATION_ID_V1" || encode_op_bytes(op))
  blake2b256Hash(OperationIdV1DomainTag, encodeSdpWithdraw(op))

func opId*(op: ActiveMessage): Result[Hash32, EncodingError] =
  ## op_id = Blake2b-256("OPERATION_ID_V1" || encode_op_bytes(op))
  let encoded = ?encodeSdpActive(op)
  ok(blake2b256Hash(OperationIdV1DomainTag, encoded))

func opId*(op: ChannelInscribePayload): Result[Hash32, EncodingError] =
  let encoded = ?encodeChannelInscribe(op)
  ok(blake2b256Hash(OperationIdV1DomainTag, encoded))

func opId*(op: ChannelConfigPayload): Result[Hash32, EncodingError] =
  let encoded = ?encodeChannelConfig(op)
  ok(blake2b256Hash(OperationIdV1DomainTag, encoded))

func opId*(op: ChannelDepositPayload): Result[Hash32, EncodingError] =
  let encoded = ?encodeChannelDeposit(op)
  ok(blake2b256Hash(OperationIdV1DomainTag, encoded))

func opId*(op: ChannelWithdrawPayload): Result[Hash32, EncodingError] =
  let encoded = ?encodeChannelWithdraw(op)
  ok(blake2b256Hash(OperationIdV1DomainTag, encoded))

func opId*(op: ChannelTransferPayload): Result[Hash32, EncodingError] =
  let encoded = ?encodeChannelTransfer(op)
  ok(blake2b256Hash(OperationIdV1DomainTag, encoded))

func opId*(op: LeaderClaimPayload): Hash32 =
  ## op_id = Blake2b-256("OPERATION_ID_V1" || encode_op_bytes(op))
  blake2b256Hash(OperationIdV1DomainTag, encodeLeaderClaim(op))

when defined(unittest) or defined(test):
  func createHashedSignedMantleTxForTest*(
      signedTx: sink SignedMantleTx,
      hash: Hash32,
  ): HashedSignedMantleTx =
    HashedSignedMantleTx(signedTx: signedTx, hash: hash)

{.pop.}
