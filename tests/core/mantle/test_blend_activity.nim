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
  ./test_helpers,
  ../../../logos_chain/core/crypto/types,
  ../../../logos_chain/core/mantle/blend_activity

from std/algorithm import fill

suite "core/mantle/blend_activity":
  test "read rejects a short input":
    let encoded = encodeActivityMetadata(mkActivityProof())
    var pos = 0
    check readActivityMetadata(
      encoded.toOpenArray(0, ActivityMetadataLen - 2), pos).error ==
        DecodingError.UnexpectedEnd
    pos = 0
    check readActivityMetadata(newSeq[byte](), pos).error ==
      DecodingError.UnexpectedEnd

  test "read rejects a non-canonical key nullifier":
    var
      encoded = encodeActivityMetadata(mkActivityProof())
      pos = 0
    encoded.toOpenArray(37, 68).fill(0xFF)
    check readActivityMetadata(encoded, pos).error ==
      DecodingError.InvalidFieldElement

  test "read rejects a non-canonical proof of selection":
    var
      encoded = encodeActivityMetadata(mkActivityProof())
      pos = 0
    encoded.toOpenArray(197, 228).fill(0xFF)
    check readActivityMetadata(encoded, pos).error ==
      DecodingError.InvalidFieldElement

  test "read leaves trailing bytes to the caller":
    var
      encoded = @(encodeActivityMetadata(mkActivityProof()))
      pos = 0
    encoded.add 0'u8
    check readActivityMetadata(encoded, pos).isOk
    check pos == ActivityMetadataLen

{.pop.}
