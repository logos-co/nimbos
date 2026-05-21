# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import std/sets
import unittest2
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

  test "validate accepts valid locator and rejects malformed/oversized ones":
    let good = Locator(cast[seq[byte]]("/ip4/127.0.0.1/tcp/30303"))
    validate(good)

    var malformedRaised = false
    try:
      validate(Locator(cast[seq[byte]]("not-a-multiaddr")))
    except AssertionDefect:
      malformedRaised = true
    check malformedRaised

    var tooLongRaised = false
    let tooLong = newSeq[byte](MaxLocatorMultiaddrBytes + 1)
    try:
      validate(Locator(tooLong))
    except AssertionDefect:
      tooLongRaised = true
    check tooLongRaised

{.pop.}
