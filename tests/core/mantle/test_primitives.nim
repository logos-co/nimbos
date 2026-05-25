# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import unittest2
import libp2p/multiaddress
import ../../../logos_chain/core/mantle/primitives

suite "core/mantle/primitives":
  test "primitive constants match expected values":
    check MaxBlockTxs == 1024
    check MantleMaxOps == 255

  test "References is MaxBlockTxs of Hash32":
    check default(References).len == MaxBlockTxs

  test "encodeValue is uint64 LE":
    let v: Value = 0xAABB_CCDD_EEFF_0011'u64
    let b = encodeValue(v)
    check b[0] == 0x11'u8
    check b[7] == 0xAA'u8

  test "encodeMetadata empty is length 0 u32 le":
    let m: Metadata = @[]
    let s = encodeMetadata(m)
    check s.len == 4
    check s[0] == 0'u8
    check s[1] == 0'u8
    check s[2] == 0'u8
    check s[3] == 0'u8

  test "encodeOpcode is single byte":
    check encodeOpcode(0x42'u8) == 0x42'u8

  test "decodeValue roundtrips encodeValue":
    let v: Value = 0xAABB_CCDD_EEFF_0011'u64
    let wire = @(encodeValue(v))
    check decodeValue(wire) == v

  test "decodeMetadata roundtrips encodeMetadata":
    let m: Metadata = @[1'u8, 2'u8, 3'u8]
    let wire = encodeMetadata(m)
    check decodeMetadata(wire) == m

  test "decodeOpcode roundtrips encodeOpcode":
    let wire = @[encodeOpcode(0x42'u8)]
    check decodeOpcode(wire) == 0x42'u8

  test "decodeLocator roundtrips encodeLocator":
    let locator = MultiAddress.init("/ip4/127.0.0.1/udp/30303/quic-v1").tryGet()
    let wire = encodeLocator(locator)
    let back = decodeLocator(wire)
    check back.data() == locator.data()

{.pop.}
