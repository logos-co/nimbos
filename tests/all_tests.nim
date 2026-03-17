# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# All tests except scenarios, which as compiled separately for mainnet and minimal

import ./testutil

import # Unit test
  ./test_peer_pool, ./test_rest_node_api, ./test_hex_utils

summarizeLongTests("AllTests")
