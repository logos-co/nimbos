# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import std/sets
import unittest2
import libp2p/multiaddress
import ../../../logos_chain/core/mantle/primitives
import ../../../logos_chain/core/sdp/state

suite "core/sdp/state":
  test "LockedNote starts with empty declaration set":
    var ln: LockedNote
    check len(ln.declarations) == 0
    check ln.lockedUntil == 0'u64

  test "DeclarationInfo fields are default-zero":
    var d: DeclarationInfo
    check d.nonce == 0'u64
    check d.service == ServiceType.bn

  test "validateLocator accepts valid locator and rejects oversized ones":
    let good = MultiAddress.init("/ip4/127.0.0.1/tcp/30303").tryGet()
    validateLocator(good)

    check MultiAddress.init("not-a-multiaddr").isErr

    var longMaStr = "/ip4/127.0.0.1/tcp/30303"
    while MultiAddress.init(longMaStr).tryGet().data().buffer.len <= MaxLocatorMultiaddrBytes:
      longMaStr &= "/ip4/1.1.1.1"
    let tooLong = MultiAddress.init(longMaStr).tryGet()
    var tooLongRaised = false
    try:
      validateLocator(tooLong)
    except AssertionDefect:
      tooLongRaised = true
    check tooLongRaised

{.pop.}
