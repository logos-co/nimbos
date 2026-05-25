# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle transaction hashing helpers.
## Spec: [v1.4 Mantle](https://nomos-tech.notion.site/v1-4-Mantle-335261aa09df8065a38acff4b25aee82)

{.push raises: [], gcsafe.}

import ./tx_types
import ../crypto/hashing
import poseidon2/[types, io]
import "../../zk/poseidon2/hasher"

const
  MantleTxHashDomainTag = "MANTLE_TXHASH_V1"
  HalfBlakeDigestBytesSize = 16

func frFromBytesUnchecked(bytes: openArray[byte]): F =
  ## Mirrors `fr_from_bytes_unchecked`: interpret little-endian bytes as field input
  ## without canonical-range checks.
  var tmp: array[31, byte]
  doAssert bytes.len <= tmp.len, "fr input chunk too large"
  for i in 0 ..< bytes.len:
    tmp[i] = bytes[i]
  F.fromBytes(tmp)

func mantleTxHashDomainFr(): F =
  frFromBytesUnchecked(MantleTxHashDomainTag.toOpenArrayByte(0, MantleTxHashDomainTag.high))

func blake2bMantleTxDigest*(txBytes: openArray[byte]): Hash32 =
  ## Classic digest step: Blake2b-256 over canonical tx bytes.
  blake2b256Hash(txBytes)

func mantleTxHash*(tx: MantleTx): ZkHash =
  ## tx_hash = Poseidon2( MANTLE_TXHASH_V1_FR || fr(blake[0..15]) || fr(blake[16..31]) )
  let txBytes = encodeMantleTx(tx)
  let classicDigest = blake2bMantleTxDigest(txBytes)

  let frA = frFromBytesUnchecked(classicDigest.toOpenArray(0, HalfBlakeDigestBytesSize - 1))
  let frB = frFromBytesUnchecked(classicDigest.toOpenArray(
    HalfBlakeDigestBytesSize, (2 * HalfBlakeDigestBytesSize) - 1))
  let preimage = [mantleTxHashDomainFr(), frA, frB]
  Poseidon2Hasher.digest(preimage).toBytes()

{.pop.}
