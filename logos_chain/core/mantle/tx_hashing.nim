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
  ./[tx_types, operations],
  ../crypto/hashing

const
  MantleTxHashDomainTag = "MANTLE_TXHASH_V1"
  OperationIdV1DomainTag = "OPERATION_ID_V1"

func mantleTxHash*(tx: MantleTx): Result[Hash32, EncodingError] =
  ## mantle_txhash = Blake2b-256("MANTLE_TXHASH_V1" || encode_mantle_tx(tx))
  let encoded = ?encodeMantleTx(tx)
  ok(blake2b256Hash(MantleTxHashDomainTag, encoded))

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
  blake2b256Hash(OperationIdV1DomainTag, @(encodeSdpWithdraw(op)))

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
  blake2b256Hash(OperationIdV1DomainTag, @(encodeLeaderClaim(op)))

{.pop.}
