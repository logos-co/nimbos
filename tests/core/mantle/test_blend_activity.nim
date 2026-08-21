# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  results,
  libp2p/crypto/ed25519/ed25519,
  ../../../logos_chain/core/crypto/types,
  ../../../logos_chain/core/mantle/blend_activity

proc mkActivityProof(seed: byte = 1): ActivityProof =
  var
    proof = ActivityProof(
      epoch: 7'u32,
      proofOfQuota: ProofOfQuota(
        keyNullifier: frFromBytesLE([seed]).get),
      proofOfSelection: frFromBytesLE([seed, 2'u8]).get)
    keyBytes: array[32, byte]
  keyBytes[0] = seed
  doAssert proof.signingKey.init(keyBytes)
  for i in 0 ..< proof.proofOfQuota.proof.len:
    proof.proofOfQuota.proof[i] = byte((i + int(seed)) mod 256)
  proof

suite "core/mantle/blend_activity":
  test "encode produces the 230-byte layout":
    let encoded = encodeActivityMetadata(mkActivityProof())
    check encoded.len == ActivityMetadataLen
    check encoded[0] == ActiveMetadataBlendType
    check encoded[1] == BlendActiveMetadataVersion
    check encoded[2] == 7'u8 # epoch u32 LE, low byte first
    check encoded[3 .. 5] == @[0'u8, 0, 0]

  test "decode round-trips an encoded proof":
    let
      original = mkActivityProof(3)
      decoded = decodeActivityMetadata(
        encodeActivityMetadata(original)).expect("valid metadata")
    check decoded == original

  test "decode rejects a wrong length":
    var encoded = encodeActivityMetadata(mkActivityProof())
    encoded.add 0'u8
    check decodeActivityMetadata(encoded).isErr
    check decodeActivityMetadata(encoded[0 ..< ActivityMetadataLen - 1]).isErr
    check decodeActivityMetadata(newSeq[byte]()).isErr

  test "decode rejects an unknown metadata type":
    var encoded = encodeActivityMetadata(mkActivityProof())
    encoded[0] = 0x02
    check decodeActivityMetadata(encoded).isErr

  test "decode rejects an unsupported version":
    var encoded = encodeActivityMetadata(mkActivityProof())
    encoded[1] = 0x99
    check decodeActivityMetadata(encoded).isErr

  test "decode rejects a non-canonical key nullifier":
    var encoded = encodeActivityMetadata(mkActivityProof())
    for i in 38 .. 69:
      encoded[i] = 0xFF
    check decodeActivityMetadata(encoded).isErr

  test "decode rejects a non-canonical proof of selection":
    var encoded = encodeActivityMetadata(mkActivityProof())
    for i in 198 .. 229:
      encoded[i] = 0xFF
    check decodeActivityMetadata(encoded).isErr

{.pop.}
