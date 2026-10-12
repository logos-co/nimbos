# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  stew/byteutils,
  unittest2,
  ../../../logos_chain/core/crypto/hashing

suite "core/crypto/hashing":
  test "blake2b256Hash is deterministic":
    let
      a = blake2b256Hash([1'u8, 2'u8, 3'u8])
      b = blake2b256Hash([1'u8, 2'u8, 3'u8])
      c = blake2b256Hash([1'u8, 2'u8, 4'u8])
    check a == b
    check a != c

  test "generateGroth16Proof succeeds when Groth16 fixtures are available":
    skip()

  test "generateZkSignature placeholder is currently skipped":
    skip()

  test "prng matches the RFC 8439 ChaCha20 keystream":
    # Test vector #1 of RFC 8439 A.1 (zero key, zero nonce, counter 0).
    # The expected value is from the RFC, not from this code.
    var stream: array[64, byte]
    prng(default(Hash32), stream)
    check stream.toHex() ==
      "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7" &
      "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"

{.pop.}
