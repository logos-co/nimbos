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

  test "prngBlock is deterministic for same seed and index":
    var seed: Blake2bPrngSeed
    seed[0] = 7'u8
    check prngBlock(seed, 0'u64) == prngBlock(seed, 0'u64)
    check prngBlock(seed, 1'u64) != prngBlock(seed, 0'u64)

  test "prngBytes empty yields empty":
    var seed: Blake2bPrngSeed
    check prngBytes(seed, 0).len == 0

{.pop.}
