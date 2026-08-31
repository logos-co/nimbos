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

func mantleTxHash*(tx: MantleTx): Hash32 =
  ## mantle_txhash = Blake2b-256("MANTLE_TXHASH_V1" || encode_mantle_tx(tx))
  blake2b256Hash(MantleTxHashDomainTag, encodeMantleTx(tx))

func opId*(op: TransferPayload): Hash32 =
  ## op_id = Blake2b-256("OPERATION_ID_V1" || encode_op_bytes(op))
  blake2b256Hash(OperationIdV1DomainTag, encodeTransfer(op))

func opId*(op: DeclarationMessage): Hash32 =
  ## op_id = Blake2b-256("OPERATION_ID_V1" || encode_op_bytes(op))
  blake2b256Hash(OperationIdV1DomainTag, encodeSdpDeclare(op))

func opId*(op: WithdrawMessage): Hash32 =
  ## op_id = Blake2b-256("OPERATION_ID_V1" || encode_op_bytes(op))
  blake2b256Hash(OperationIdV1DomainTag, @(encodeSdpWithdraw(op)))

func opId*(op: ActiveMessage): Hash32 =
  ## op_id = Blake2b-256("OPERATION_ID_V1" || encode_op_bytes(op))
  blake2b256Hash(OperationIdV1DomainTag, encodeSdpActive(op))

func opId*(op: ChannelInscribePayload): Hash32 =
  blake2b256Hash(OperationIdV1DomainTag, encodeChannelInscribe(op))

func opId*(op: ChannelConfigPayload): Hash32 =
  blake2b256Hash(OperationIdV1DomainTag, encodeChannelConfig(op))

func opId*(op: ChannelDepositPayload): Hash32 =
  blake2b256Hash(OperationIdV1DomainTag, encodeChannelDeposit(op))

func opId*(op: ChannelWithdrawPayload): Hash32 =
  blake2b256Hash(OperationIdV1DomainTag, encodeChannelWithdraw(op))

func opId*(op: ChannelTransferPayload): Hash32 =
  blake2b256Hash(OperationIdV1DomainTag, encodeChannelTransfer(op))

func opId*(op: LeaderClaimPayload): Hash32 =
  ## op_id = Blake2b-256("OPERATION_ID_V1" || encode_op_bytes(op))
  blake2b256Hash(OperationIdV1DomainTag, encodeLeaderClaim(op))

{.pop.}
