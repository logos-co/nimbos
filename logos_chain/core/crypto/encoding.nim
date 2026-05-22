# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Little-endian, length-prefixed, and fixed-size **byte** encoders shared across
## Bedrock (block ids, PRNG, Ed25519 wire, Groth16 bytes, Mantle wire, etc.).
## Spec: [v1.3 Mantle Transaction Encoding](https://nomos-tech.notion.site/v1-3-Mantle-Transaction-Encoding-335261aa09df8051a8a6f325aa41f6a7)

{.push raises: [], gcsafe.}

import libp2p/crypto/ed25519/ed25519
import stew/endians2


func encodeLe*[T: SomeUnsignedInt](value: T): array[sizeof(T), byte] =
  value.toBytesLE()

func encodeByte*(value: byte): byte =
  value


func encodeU32LeLenPrefixed*(data: openArray[byte]): seq[byte] =
  ## ``UINT32`` length (LE) then payload (Inscription, Metadata, …).
  doAssert data.len <= int(high(uint32)),
    "length-prefixed data exceeds UINT32 range"
  result = @(encodeLe(uint32(data.len)))
  result.add(data)

func encodeU16LeLenPrefixed*(data: openArray[byte]): seq[byte] =
  ## ``UINT16`` length (LE) then payload (e.g. single Locator).
  doAssert data.len <= int(high(uint16)),
    "length-prefixed data exceeds UINT16 range"
  result = @(encodeLe(uint16(data.len)))
  result.add(data)


func encodeGroth16*(proof: array[128, byte]): array[128, byte] =
  ## Groth16 = 128BYTE (pi_a:32 || pi_b:64 || pi_c:32) — compressed on-wire layout.
  proof

func encodeFieldElement*(value: array[32, byte]): array[32, byte] =
  ## FieldElement = 32BYTE (BN254 field element, little-endian).
  value

func encodeHash32*(value: array[32, byte]): array[32, byte] =
  ## Hash32 = 32BYTE.
  value

func encodeEd25519PublicKey*(value: EdPublicKey): array[32, byte] =
  ## Ed25519 public key = 32BYTE.
  var buf: array[EdPublicKeySize, byte]
  let written = toBytes(value, buf)
  doAssert written == EdPublicKeySize, "failed to encode Ed25519 public key"
  buf

func encodeEd25519Signature*(value: EdSignature): array[64, byte] =
  ## Ed25519 signature = 64BYTE.
  var buf: array[EdSignatureSize, byte]
  let written = toBytes(value, buf)
  doAssert written == EdSignatureSize, "failed to encode Ed25519 signature"
  buf

func encodeZkSignature*(value: array[128, byte]): array[128, byte] =
  ## ZkSignature = Groth16 (128-byte wire).
  encodeGroth16(value)

func encodeZkPublicKey*(value: array[32, byte]): array[32, byte] =
  ## ZkPublicKey = FieldElement (32-byte).
  encodeFieldElement(value)

{.pop.}
