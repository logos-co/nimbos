# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  stew/byteutils,
  ../../logos_chain/core/utils

suite "core/utils":
  test "isUtf8 accepts empty input":
    check isUtf8([])

  test "isUtf8 accepts ASCII":
    check isUtf8("logos-devnet".toBytes)

  test "isUtf8 accepts 2-, 3- and 4-byte sequences":
    check isUtf8("ü€😀".toBytes)

  test "isUtf8 accepts the boundary code points":
    for ok in [
        @[byte 0xc2, 0x80],             # U+0080, smallest 2-byte
        @[byte 0xdf, 0xbf],             # U+07FF, largest 2-byte
        @[byte 0xe0, 0xa0, 0x80],       # U+0800, smallest 3-byte
        @[byte 0xed, 0x9f, 0xbf],       # U+D7FF, just below surrogates
        @[byte 0xee, 0x80, 0x80],       # U+E000, just above surrogates
        @[byte 0xef, 0xbf, 0xbf],       # U+FFFF, largest 3-byte
        @[byte 0xf0, 0x90, 0x80, 0x80], # U+10000, smallest 4-byte
        @[byte 0xf4, 0x8f, 0xbf, 0xbf]]: # U+10FFFF, largest code point
      check isUtf8(ok)

  test "isUtf8 rejects invalid lead bytes":
    for bad in [
        @[byte 0x80],                   # continuation byte as lead
        @[byte 0xc0, 0x80],             # overlong 2-byte lead
        @[byte 0xc1, 0xbf],             # overlong 2-byte lead
        @[byte 0xf5, 0x80, 0x80, 0x80], # above U+10FFFF lead
        @[byte 0xff]]:
      check not isUtf8(bad)

  test "isUtf8 rejects overlong forms":
    for bad in [
        @[byte 0xe0, 0x80, 0x80],       # U+0000 as 3 bytes
        @[byte 0xe0, 0x9f, 0xbf],       # U+07FF as 3 bytes
        @[byte 0xf0, 0x80, 0x80, 0x80], # U+0000 as 4 bytes
        @[byte 0xf0, 0x8f, 0xbf, 0xbf]]: # U+FFFF as 4 bytes
      check not isUtf8(bad)

  test "isUtf8 rejects surrogates and code points above U+10FFFF":
    for bad in [
        @[byte 0xed, 0xa0, 0x80],       # U+D800
        @[byte 0xed, 0xbf, 0xbf],       # U+DFFF
        @[byte 0xf4, 0x90, 0x80, 0x80]]: # U+110000
      check not isUtf8(bad)

  test "isUtf8 rejects truncated and malformed continuations":
    for bad in [
        @[byte 0xc3],                   # 2-byte lead, no continuation
        @[byte 0xe2, 0x82],             # 3-byte lead, one continuation
        @[byte 0xf0, 0x9f, 0x98],       # 4-byte lead, two continuations
        @[byte 0xc3, 0x41],             # ASCII where continuation expected
        @[byte 0xe2, 0x82, 0xc3],       # lead where continuation expected
        @[byte 0x41, 0x80]]:            # stray continuation after ASCII
      check not isUtf8(bad)

{.pop.}
