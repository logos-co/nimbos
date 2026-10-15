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
  ./[primitives, operations, proofs]

export primitives, operations, proofs

type
  MantleTx* = object
    ops*: seq[Op]

  SignedMantleTx* = object
    tx*: MantleTx
    opProofs*: seq[OpProof]


func encodeMantleTx*(tx: MantleTx): Result[seq[byte], EncodingError] =
  ## MantleTx = OpCount (u8) || *Op
  encodeOps(tx.ops)

# TODO (perf): `encodeSignedMantleTx` builds byte buffers from the inside out,
# triggering intermediate seq[byte] heap allocations and concatenation copies (e.g. `res.add`).
# Optimize by streaming into an `OutputStreamHandle` (faststreams) across the encoder hierarchy
# (`encode(stream, tx)`, `encode(stream, op.payload)`, etc.). This eliminates all intermediate buffers
# and allows block serializers (e.g. `ValidBlock.encode`) to stream transactions directly into the
# wire buffer in a single pass.
func encodeSignedMantleTx*(signedTx: SignedMantleTx): Result[seq[byte], EncodingError] =
  ## SignedMantleTx = MantleTx || OpsProofs
  var res = ?encodeMantleTx(signedTx.tx)
  let proofsBytes = ?encodeOpsProofs(signedTx.tx.ops, signedTx.opProofs)
  res.add(proofsBytes)
  ok(res)

func byteLen*(tx: MantleTx): int =
  ## Exact wire byte length of a MantleTx without allocating buffers.
  byteLen(tx.ops)

func byteLen*(tx: SignedMantleTx): int =
  ## Exact wire byte length of a SignedMantleTx without allocating buffers.
  byteLen(tx.tx) + byteLen(tx.opProofs)


{.pop.}
