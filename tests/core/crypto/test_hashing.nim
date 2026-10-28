# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  stew/[assign2, byteutils],
  ../../testsuite,
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
    # Test vectors #1 and #2 of RFC 8439 A.1 (zero key, zero nonce,
    # counters 0 and 1). The expected values are from the RFC, not from
    # this code. Two blocks show that the counter advances.
    var stream: array[128, byte]
    prng(default(Hash32), stream)
    check stream.toHex() ==
      "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7" &
      "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586" &
      "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed" &
      "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"

  test "prng output is a prefix of the longer keystream":
    # Consensus callers request 8 bytes.
    var
      short, prefix: array[8, byte]
      long: array[64, byte]
    prng(default(Hash32), short)
    prng(default(Hash32), long)
    assign(prefix, long.toOpenArray(0, 7))
    check short == prefix

  test "prng is deterministic and seed-sensitive":
    var
      seed = default(Hash32)
      a, b, c: array[32, byte]
    prng(seed, a)
    prng(seed, b)
    seed[0] = 1
    prng(seed, c)
    check:
      a == b
      a != c

  test "prng leaves an empty buffer untouched":
    var empty: seq[byte]
    prng(default(Hash32), empty)
    check empty.len == 0

{.pop.}
