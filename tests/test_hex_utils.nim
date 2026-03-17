# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import std/strutils
import ./testutil
import ../logos_chain/utils/hex_utils

suite "Hex utils":
  test "accepts plain hex of correct length":
    let value = "0".repeat(64)
    check isValidHexWithOptional0x(value, 64)

  test "accepts 0x-prefixed hex of correct length":
    let body = "0".repeat(64)
    check isValidHexWithOptional0x("0x" & body, 64)

  test "rejects wrong lengths":
    check not isValidHexWithOptional0x("0".repeat(63), 64)
    check not isValidHexWithOptional0x("0".repeat(65), 64)

  test "rejects non-hex characters":
    check not isValidHexWithOptional0x("g".repeat(64), 64)
    check not isValidHexWithOptional0x("0x" & "z".repeat(64), 64)

{.pop.}

