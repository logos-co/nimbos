# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [1.0.1 Common Cryptographic Components](https://nomos-tech.notion.site/1-0-1-Common-Cryptographic-Components-1fd261aa09df81ac8ebbe0111e2c2d84)

{.push raises: [], gcsafe.}

import nimcrypto/blake2
import poseidon2/[types, io, sponge]
import ./encoding

# ---------------------------------------------------------------------------
# Core hashing and proof types
# ---------------------------------------------------------------------------

type
  Hash32* = array[32, byte]
  ## BN254 32-byte field element as returned by Poseidon2 sponge (LE); Mantle **``ZkHash``** wire.
  ZkHash* = Hash32
  BlockId* = Hash32
  Blake2bPrngSeed* = array[64, byte]
  Blake2bPrngBlock* = array[64, byte]

  ## Spec wire-sized Groth16 proof encoding:
  ## pi_a (32 bytes) || pi_b (64 bytes) || pi_c (32 bytes).
  ## This keeps only x-coordinates and is intended for transport/storage.
  ## TODO: implement/verify the exact compressed BN254 proof codec
  ## (point sign bits, infinity representation, and canonical byte order).
  CompressedGroth16Proof* = array[128, byte]
  ## Placeholder alias until zk proof encoding is finalized.
  ZkSignature* = CompressedGroth16Proof

const
  CompressedGroth16ProofBytes* = 128

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
  Sponge.digest(data).toBytes()

# ---------------------------------------------------------------------------
# Public hashing / PRNG utilities
# ---------------------------------------------------------------------------

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
