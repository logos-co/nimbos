# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Hashing and PRNG over common cryptographic types (see ``encoding``).
## Spec: [Common Cryptographic Components v1.2.0](https://github.com/logos-co/logos-lips/blob/fddc2c1911626f7b1949360b8924bb6c05252bff/docs/blockchain/raw/common-cryptographic-components.md)

{.push raises: [], gcsafe.}

import
  std/algorithm,
  bearssl/blockx,
  nimcrypto/blake2,
  stew/staticfor,
  ./types
export types

func blake2b256Hash*(domainTag: string, data: openArray[byte]): Hash32 =
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

func prng*(seed: Hash32, output: var openArray[byte]) =
  ## Writes the first `output.len` bytes of the ChaCha20 keystream of `seed`.
  ## Spec: [ChaCha20-Based PRNG Construction](https://github.com/logos-co/logos-lips/blob/fddc2c1911626f7b1949360b8924bb6c05252bff/docs/blockchain/raw/common-cryptographic-components.md#chacha20-based-prng-construction)
  # bearssl implements RFC 8439 (96-bit nonce, 32-bit counter). With a zero
  # nonce, its keystream is equal to the original variant that the spec
  # names, for the first 2^32 blocks.
  const nonce = default(array[12, byte])
  if output.len > 0:
    output.fill(0'u8)
    discard chacha20CtRun(
      addr seed, addr nonce, 0'u32,
      addr output[0], csize_t(output.len))

{.pop.}
