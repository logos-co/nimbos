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
  ./test_poseidon_hasher,
  ./core/crypto/test_hashing,
  ./core/crypto/test_types,
  ./core/mantle/test_primitives,
  ./core/mantle/test_operations,
  ./core/mantle/test_proofs,
  ./core/mantle/test_tx_types,
  ./core/mantle/test_tx_bincode,
  ./core/mantle/test_tx_hashing,
  ./core/mantle/test_utxo,
  ./core/mantle/test_declaration_id,
  ./core/test_block_types,
  ./core/test_block_bincode,
  ./core/test_block_validation,
  ./core/test_local_tree,
  ./consensus/test_clock,
  ./chain/test_genesis,
  ./chain/test_genesis_params,
  ./chain/test_devnet_genesis_mantle_tx,
  ./chain/test_chain_wiring,
  ./utils/test_hash_trie_map,
  ./utils/test_dynamic_merkle_tree,
  ./ledger/sdp/test_state,
  ./ledger/sdp/test_registry,
  ./ledger/sdp/ops/test_declare,
  ./ledger/sdp/ops/test_withdraw,
  ./ledger/sdp/ops/test_active,
  ./ledger/test_utxo_store,
  ./ledger/test_cryptarchia,
  ./ledger/test_ledger,
  ./ledger/test_gas,
  ./ledger/test_block_density,
  ./ledger/test_stake_inference,
  ./ledger/test_epoch_state,
  ./ledger/test_header_apply,
  ./ledger/test_channel_inscribe,
  ./ledger/test_channel_config,
  ./ledger/test_channel_deposit,
  ./ledger/test_channel_withdraw,
  ./ledger/test_channel_round_robin,
  ./ledger/test_pol_verifier,
  ./ledger/test_poc_verifier,
  ./logos_chain/sync/test_framing,
  ./logos_chain/sync/test_types,
  ./logos_chain/sync/test_ibd,
  ./zk/test_circuits,
  ./zk/test_pol,
  ./zk/test_poc,
  ./zk/test_pol_lottery,
  ./zk/test_zksign,
  ./zk/groth16/test_vk_json,
  ./zk/groth16/test_verifier

summarizeLongTests("AllTests")

{.pop.}
