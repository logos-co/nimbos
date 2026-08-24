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
  ./test_helpers,
  ../../../logos_chain/core/crypto/hashing,
  ../../../logos_chain/ledger/sdp/blend_token

proc mkToken(seed: byte = 1): BlendingToken =
  var
    token = BlendingToken(
      proofOfQuota: ProofOfQuota(keyNullifier: frFromBytesLE([seed]).get),
      selectionRandomness: frFromBytesLE([seed, 7'u8]).get)
    keyBytes: array[32, byte]
  keyBytes[0] = seed
  doAssert token.signingKey.init(keyBytes)
  token

suite "ledger/sdp/blend_token":
  test "digest length is a hash parameter, not a truncation":
    let data = @[byte 1, 2, 3]
    # An 8-byte digest differs from the first 8 bytes of a 64-byte digest.
    check @(blake2bShort(data, 8)) != blake2b512Hash(data)[0 ..< 8]

  test "tokenParams matches the spec examples":
    # chi = ceil(log2(5*2 + 1)) = 4 -> one digest byte.
    # threshold = chi - nu - theta = 4 - 2 - 1 = 1.
    let small = tokenParams(5, 2, 1).expect("params")
    check small.byteLen == 1
    check small.threshold == 1

    # chi = ceil(log2(2000*2 + 1)) = 12 -> two digest bytes.
    let wide = tokenParams(2000, 2, 1).expect("params")
    check wide.byteLen == 2
    # threshold = 12 - ceil(log2(3)) - 1 = 9
    check wide.threshold == 9

  test "threshold saturates at zero":
    # chi = 0, nu = ceil(log2(128)) = 7, theta = 1 -> clamped to 0.
    let params = tokenParams(0, 127, 1).expect("params")
    check params.threshold == 0
    check params.byteLen == 0

  test "tokenParams rejects overflowing inputs":
    check tokenParams(high(uint64), 2, 1).isErr
    check tokenParams(1, high(uint64), 1).isErr

  test "coreQuota rounds up":
    # C = 100 * 0.5 = 50; 50 * 2 / 7 = 14.28... -> 15.
    check coreQuota(100, 0.5, 2, 7).expect("quota") == 15
    # Exact division stays exact.
    check coreQuota(100, 0.5, 2, 10).expect("quota") == 10

  test "coreQuota rejects a quota with no uint64 image":
    # A frequency this large overshoots 2^64 whatever the network size.
    check coreQuota(1'u64 shl 62, 1e30, 4, 1).isErr
    # 0 * Inf is NaN, which compares false against every bound.
    check coreQuota(0, Inf, 1, 1).isErr

  test "hammingDistance is deterministic and bounded":
    let
      token = mkToken()
      randomness = frFromBytesLE([byte 9]).get
      d1 = hammingDistance(token, randomnessDigest(randomness, 2), 2)
    check d1 == hammingDistance(token, randomnessDigest(randomness, 2), 2)
    check d1 <= 16
    check hammingDistance(token, randomnessDigest(randomness, 1), 1) <= 8

{.pop.}
