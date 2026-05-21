# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import unittest2
import ../../../logos_chain/core/crypto/encoding

suite "core/crypto/encoding":
  test "encodeLe infers output width from unsigned input type":
    let le16 = encodeLe(0x0123'u16)
    let le32 = encodeLe(0x0123_4567'u32)
    let le64 = encodeLe(0x0123_4567_89AB_CDEF'u64)
    check le16.len == 2
    check le32.len == 4
    check le64.len == 8
    check le16 == [0x23'u8, 0x01'u8]
    check le32 == [0x67'u8, 0x45'u8, 0x23'u8, 0x01'u8]

  test "encodeLe explicit generic and inferred forms match":
    let v16 = 0xBEEF'u16
    let v32 = 0xDEAD_BEEF'u32
    let v64 = 0x0123_4567_89AB_CDEF'u64
    check encodeLe(v16) == encodeLe[uint16](v16)
    check encodeLe(v32) == encodeLe[uint32](v32)
    check encodeLe(v64) == encodeLe[uint64](v64)

  test "encodeLe uint64 little-endian":
    let le = encodeLe(0x0102_0304_0506_0708'u64)
    check le[0] == 8'u8
    check le[7] == 1'u8

  test "encodeU32LeLenPrefixed length then bytes":
    let s = encodeU32LeLenPrefixed([9'u8, 8'u8, 7'u8])
    check s.len == 4 + 3
    check s[0] == 3'u8
    check s[4] == 9'u8
    check s[5] == 8'u8
    check s[6] == 7'u8

  test "encodeU16LeLenPrefixed length then bytes":
    let s = encodeU16LeLenPrefixed([0xAB'u8, 0xCD'u8])
    check s.len == 2 + 2
    check s[0] == 2'u8
    check s[2] == 0xAB'u8

  test "encodeFieldElement and encodeHash32 are identity on bytes":
    var a: array[32, byte]
    a[0] = 0x11'u8
    check encodeFieldElement(a) == a
    check encodeHash32(a) == a

{.pop.}
