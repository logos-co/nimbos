# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import unittest2
import ../../../logos_chain/core/mantle/primitives

suite "core/mantle/primitives":
  test "primitive constants match expected values":
    check MaxBlockTxs == 1024
    check MantleMaxOps == 255

  test "References is MaxBlockTxs of Hash32":
    check default(References).len == MaxBlockTxs

{.pop.}
