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
  ./test_peer_pool,
  ./test_logos_p2p,
  ./test_api_handlers,
  ./test_deployment_settings,
  ./bedrock/crypto/test_hashing,
  ./bedrock/crypto/test_encoding,
  ./bedrock/mantle/test_primitives,
  ./bedrock/mantle/test_operations,
  ./bedrock/mantle/test_proofs,
  ./bedrock/mantle/test_tx_types,
  ./bedrock/mantle/test_tx_encoding,
  ./bedrock/mantle/test_tx_decoding,
  "./bedrock/block/test_block_types",
  "./bedrock/block/test_genesis",
  ./bedrock/sdp/test_state

summarizeLongTests("AllTests")

{.pop.}
