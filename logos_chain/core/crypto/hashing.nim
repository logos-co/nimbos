# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Hashing and PRNG over common cryptographic types (see ``encoding``).
## Spec: [1.0.1 Common Cryptographic Components](https://nomos-tech.notion.site/1-0-1-Common-Cryptographic-Components-1fd261aa09df81ac8ebbe0111e2c2d84)

{.push raises: [], gcsafe.}

import nimcrypto/blake2
import poseidon2/sponge
import ./types
export types


func blake2b256Hash*(data: openArray[byte]): Hash32 =
  ## Spec reference (common cryptographic components):
  ## https://nomos-tech.notion.site/1-0-0-Common-Cryptographic-Components-1fd261aa09df81ac8ebbe0111e2c2d84#1fd261aa09df81b3890fcc4f9606ee9e
  ## Returns BLAKE2b-256(data) as a 32-byte **``Hash32``**.
  var ctx {.noinit.}: Blake2bContext[256]
  ctx.init()
  ctx.update(data)
  let digest = ctx.finish()
  digest.data

func generateGroth16Proof*(): CompressedGroth16Proof =
  ## Placeholder: return zeroed compressed Groth16 bytes.
  static: doAssert CompressedGroth16ProofBytes == sizeof(CompressedGroth16Proof)
  default(CompressedGroth16Proof)

func generateZkSignature*(): ZkSignature =
  ## Placeholder: return opaque zeroed signature bytes.
  default(ZkSignature)

func poseidon2Hash*(data: openArray[byte]): ZkHash =
  ## Poseidon2 (BN254, t=3) sponge hash over input bytes.
  ## Returns canonical 32-byte little-endian field element encoding.
  ## TODO(zk): replace this direct sponge call with `Poseidon2Hasher` when ready.
  Sponge.digest(data).toBytes()


func prngBlock*(seed: Blake2bPrngSeed, index: uint64): Blake2bPrngBlock =
  ## Spec reference (BLAKE2b-based PRNG):
  ## https://nomos-tech.notion.site/1-0-0-Common-Cryptographic-Components-1fd261aa09df81ac8ebbe0111e2c2d84#1fd261aa09df81b3890fcc4f9606ee9e
  ## Spec construction:
  ## PRNG(seed, i) = BLAKE2b(seed || encode_u64_le(i), out_len=64)
  var input: array[72, byte]
  let indexLe = encodeLe(index)
  for i in 0 .. 63:
    input[i] = seed[i]
  for i in 0 .. 7:
    input[64 + i] = indexLe[i]

  var ctx {.noinit.}: Blake2bContext[512]
  ctx.init()
  ctx.update(input)
  let digest = ctx.finish()
  digest.data

func prngBytes*(seed: Blake2bPrngSeed, byteLen: Natural): seq[byte] =
  ## Spec reference (PRNG expansion by concatenation):
  ## https://nomos-tech.notion.site/1-0-0-Common-Cryptographic-Components-1fd261aa09df81ac8ebbe0111e2c2d84#1fd261aa09df81b3890fcc4f9606ee9e
  ## Expands PRNG output by concatenating 64-byte PRNG blocks.
  result = newSeq[byte](byteLen)
  if byteLen == 0:
    return

  var written = 0
  var index = 0'u64
  while written < byteLen:
    let blk = prngBlock(seed, index)
    let remaining = byteLen - written
    let take = min(64, remaining)
    for j in 0 ..< take:
      result[written + j] = blk[j]
    written += take
    inc index

{.pop.}
