# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle transaction hashing helpers.
## Spec: [v1.4 Mantle](https://nomos-tech.notion.site/v1-4-Mantle-335261aa09df8065a38acff4b25aee82)

{.push raises: [], gcsafe.}

import ./[tx_types, operations]
import ../crypto/hashing
import ../../zk/poseidon2/hasher

const
  MantleTxHashDomainTag = "MANTLE_TXHASH_V1"
  OperationIdV1DomainTag = "OPERATION_ID_V1"
  HalfBlakeDigestBytesSize = 16

func blake2bWithDomain(domainTag: string, payload: openArray[byte]): Hash32 =
  var preimage = newSeqOfCap[byte](domainTag.len + payload.len)
  for c in domainTag:
    preimage.add(byte(ord(c)))
  preimage.add(payload)
  blake2b256Hash(preimage)

func mantleTxHashDomainField(): FieldElement {.inline.} =
  frFromBytesLE(
    MantleTxHashDomainTag.toOpenArrayByte(0, MantleTxHashDomainTag.high)).get

func mantleTxHash*(tx: MantleTx): ZkHash =
  ## tx_hash = Poseidon2( MANTLE_TXHASH_V1_FR || fr(blake[0..15]) || fr(blake[16..31]) )
  let classicDigest = blake2b256Hash(encodeMantleTx(tx))

  let feA = frFromBytesLE(
    classicDigest.toOpenArray(0, HalfBlakeDigestBytesSize - 1)).get
  let feB = frFromBytesLE(classicDigest.toOpenArray(
    HalfBlakeDigestBytesSize, (2 * HalfBlakeDigestBytesSize) - 1)).get
  let preimage = [mantleTxHashDomainField(), feA, feB]
  Poseidon2Hasher.digest(preimage).toBytes()

func opId*(op: TransferPayload): Hash32 =
  ## op_id = Blake2b-256("OPERATION_ID_V1" || encode_op_bytes(op))
  blake2bWithDomain(OperationIdV1DomainTag, encodeTransfer(op))

{.pop.}
