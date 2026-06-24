# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle transaction hashing helpers.
## Spec: [v1.5.0 Mantle](https://nomos-tech.notion.site/1-5-0-Mantle-33d261aa09df8051b0d0cd4d5ddade85)
## Wire encoding/decoding: [v1.4.1 Mantle Transaction Encoding](https://nomos-tech.notion.site/1-4-1-Mantle-Transaction-Encoding-33e261aa09df8050beb6c9b72a042217)

{.push raises: [], gcsafe.}

import
  ./[tx_types, operations],
  ../crypto/hashing

const
  MantleTxHashDomainTag = "MANTLE_TXHASH_V1"
  OperationIdV1DomainTag = "OPERATION_ID_V1"

func blake2bWithDomain(domainTag: string, payload: openArray[byte]): Hash32 =
  var preimage = newSeqOfCap[byte](domainTag.len + payload.len)
  for c in domainTag:
    preimage.add(byte(ord(c)))
  preimage.add(payload)
  blake2b256Hash(preimage)

func mantleTxHash*(tx: MantleTx): Hash32 =
  ## mantle_txhash = Blake2b-256("MANTLE_TXHASH_V1" || encode_mantle_tx(tx))
  blake2bWithDomain(MantleTxHashDomainTag, encodeMantleTx(tx))

func opId*(op: TransferPayload): Hash32 =
  ## op_id = Blake2b-256("OPERATION_ID_V1" || encode_op_bytes(op))
  blake2bWithDomain(OperationIdV1DomainTag, encodeTransfer(op))

func opId*(op: ChannelInscribePayload): Hash32 =
  blake2bWithDomain(OperationIdV1DomainTag, encodeChannelInscribe(op))

func opId*(op: ChannelConfigPayload): Hash32 =
  blake2bWithDomain(OperationIdV1DomainTag, encodeChannelConfig(op))

func opId*(op: ChannelDepositPayload): Hash32 =
  blake2bWithDomain(OperationIdV1DomainTag, encodeChannelDeposit(op))

func opId*(op: ChannelWithdrawPayload): Hash32 =
  blake2bWithDomain(OperationIdV1DomainTag, encodeChannelWithdraw(op))

{.pop.}
