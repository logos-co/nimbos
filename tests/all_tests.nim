# nimbos
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
  ./core/crypto/test_hashing,
  ./core/crypto/test_types,
  ./core/mantle/test_primitives,
  ./core/mantle/test_operations,
  ./core/mantle/test_proofs,
  ./core/mantle/test_tx_types,
  ./core/mantle/test_tx_hashing,
  ./core/mantle/test_utxo,
  ./core/test_block_types,
  ./core/test_genesis,
  ./core/sdp/test_state,
  ./utils/test_hash_trie_map,
  ./utils/test_dynamic_merkle_tree,
  ./ledger/test_utxo_store,
  ./ledger/test_cryptarchia,
  ./ledger/test_ledger,
  ./test_poseidon_hasher

summarizeLongTests("AllTests")

{.pop.}
