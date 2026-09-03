# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Hashing and PRNG over common cryptographic types (see ``encoding``).
## Spec: [Common Cryptographic Components v1.0.2](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/common-cryptographic-components.md)

{.push raises: [], gcsafe.}

import
  nimcrypto/blake2,
  stew/staticfor,
  ./types
export types


func blake2b256Hash*(domainTag: string, data: openArray[byte]): Hash32 =
  ## Spec reference (common cryptographic components):
  ## https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/common-cryptographic-components.md#blake2bgeneral-purpose-hashing
  ## Returns BLAKE2b-256([domainTag ||] data) as a 32-byte **``Hash32``**.
  var ctx {.noinit.}: Blake2bContext[256]
  ctx.init()
  if domainTag.len > 0:
    ctx.update(domainTag.toOpenArrayByte(0, domainTag.high))
  ctx.update(data)
  let digest = ctx.finish()
  digest.data

template blake2b256Hash*(data: openArray[byte]): Hash32 =
  blake2b256Hash("", data)

func blake2b512Hash*(data: openArray[byte]): array[64, byte] =
  ## Returns BLAKE2b-512(data) as a 64-byte digest.
  var ctx {.noinit.}: Blake2bContext[512]
  ctx.init()
  ctx.update(data)
  ctx.finish().data

func blake2bShort*(data: openArray[byte], outLen: uint64): array[8, byte] =
  ## BLAKE2b digest of ``outLen`` bytes (1..8) in a fixed buffer; bytes
  ## past ``outLen`` stay zero.
  # A fixed buffer keeps consensus state allocation-free.
  doAssert outLen >= 1 and outLen <= 8,
    "blake2bShort: digest width must be 1..8"
  var digest: array[8, byte]
  staticFor i, 1 .. 8:
    if i == int(outLen):
      var ctx {.noinit.}: Blake2bContext[i * 8]
      ctx.init()
      ctx.update(data)
      digest[0 ..< i] = ctx.finish().data
  digest

func generateGroth16Proof*(): CompressedGroth16Proof =
  ## Placeholder: return zeroed compressed Groth16 bytes.
  static: doAssert CompressedGroth16ProofBytes == sizeof(CompressedGroth16Proof)
  DefaultCompressedGroth16Proof

func generateZkSignature*(): ZkSignature =
  ## Placeholder: return opaque zeroed signature bytes.
  DefaultZkSignature


func prngBlock*(seed: Blake2bPrngSeed, index: uint64): Blake2bPrngBlock =
  ## Spec reference (BLAKE2b-based PRNG):
  ## https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/common-cryptographic-components.md#blake2b-based-prng-construction
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
  ## https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/common-cryptographic-components.md#blake2b-based-prng-construction
  ## Expands PRNG output by concatenating 64-byte PRNG blocks.
  var res = newSeq[byte](byteLen)
  if byteLen == 0:
    return res

  var written = 0
  var index = 0'u64
  while written < byteLen:
    let blk = prngBlock(seed, index)
    let remaining = byteLen - written
    let take = min(64, remaining)
    for j in 0 ..< take:
      res[written + j] = blk[j]
    written += take
    inc index
  res

{.pop.}
