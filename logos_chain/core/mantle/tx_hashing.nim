# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle transaction hashing helpers.
## Spec: [v1.4 Mantle](https://nomos-tech.notion.site/v1-4-Mantle-335261aa09df8065a38acff4b25aee82)

{.push raises: [], gcsafe.}

import std/options

import ./tx_types
import ./tx_encoding
import ../crypto/hashing
import poseidon2/[types, io]
import "../../zk/poseidon2/hasher"

const
  MantleTxHashDomainTag = "MANTLE_TXHASH_V1"
  HalfBlakeDigestBytesSize = 16

func mantleTxHashDomainFr(): F =
  frFromBytesLE(MantleTxHashDomainTag.toOpenArrayByte(0, MantleTxHashDomainTag.high)).get

func blake2bMantleTxDigest*(txBytes: openArray[byte]): Hash32 =
  ## Classic digest step: Blake2b-256 over canonical tx bytes.
  blake2b256Hash(txBytes)

func mantleTxHash*(tx: MantleTx): ZkHash =
  ## tx_hash = Poseidon2( MANTLE_TXHASH_V1_FR || fr(blake[0..15]) || fr(blake[16..31]) )
  let 
    txBytes = encodeMantleTx(tx)
    classicDigest = blake2bMantleTxDigest(txBytes)
    frA = frFromBytesLE(classicDigest.toOpenArray(0, HalfBlakeDigestBytesSize - 1)).get
    frB = frFromBytesLE(classicDigest.toOpenArray(
    HalfBlakeDigestBytesSize,
    (2 * HalfBlakeDigestBytesSize) - 1)).get
    preimage = [mantleTxHashDomainFr(), frA, frB]
  Poseidon2Hasher.digest(preimage).toBytes()

{.pop.}
