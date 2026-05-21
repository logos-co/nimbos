# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle transaction hashing helpers.
## Spec: [v1.4 Mantle](https://nomos-tech.notion.site/v1-4-Mantle-335261aa09df8065a38acff4b25aee82)

{.push raises: [], gcsafe.}

import ./[tx_types, tx_encoding]
import ../crypto/hashing

const
  MantleTxHashDomainTag = "MANTLE_TXHASH_V1"

func blake2bWithMantleTxDomain*(txBytes: openArray[byte]): Hash32 =
  var preimage: seq[byte] = @[]
  for c in MantleTxHashDomainTag:
    preimage.add(byte(ord(c)))
  preimage.add(txBytes)
  blake2b256Hash(preimage)

func mantleTxHash*(tx: MantleTx): ZkHash =
  ## Placeholder classic hash (Blake2b-256):
  ## h.update("MANTLE_TXHASH_V1")
  ## h.update(encode(tx))
  ## classic_digest = h.digest()
  ##
  ## TODO: once zk/poseidon2/hasher exists in this target, derive ZkHash by
  ## feeding two little-endian field chunks from classic_digest into ZkHasher.
  let txBytes = encodeMantleTx(tx)
  let classicDigest = blake2bWithMantleTxDomain(txBytes)
  classicDigest

{.pop.}
