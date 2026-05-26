# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle transaction hashing helpers.
## Spec: [v1.4 Mantle](https://nomos-tech.notion.site/v1-4-Mantle-335261aa09df8065a38acff4b25aee82)

{.push raises: [], gcsafe.}

import ./[tx_types, operations], ../crypto/hashing

const
  MantleTxHashDomainTag = "MANTLE_TXHASH_V1"
  OperationIdV1DomainTag = "OPERATION_ID_V1"

func blake2bWithDomain(domainTag: string, payload: openArray[byte]): Hash32 =
  var preimage = newSeqOfCap[byte](domainTag.len + payload.len)
  for c in domainTag:
    preimage.add(byte(ord(c)))
  preimage.add(payload)
  blake2b256Hash(preimage)

func mantleTxHash*(tx: MantleTx): ZkHash =
  ## tx_hash = Blake2b-256("MANTLE_TXHASH_V1" || encode(tx))
  ## TODO: once zk/poseidon2/hasher exists in this target, derive ZkHash by
  ## feeding two little-endian field chunks from classic_digest into ZkHasher.
  blake2bWithDomain(MantleTxHashDomainTag, encodeMantleTx(tx))

func opId*(op: TransferPayload): Hash32 =
  ## op_id = Blake2b-256("OPERATION_ID_V1" || encode_op_bytes(op))
  blake2bWithDomain(OperationIdV1DomainTag, encodeTransfer(op))

{.pop.}
