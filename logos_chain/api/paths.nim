# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## NOTE: The Logos HTTP paths below are not specified in any current Logos Chain
## research/spec document. Their concrete values presently follow the Rust
## `logos-blockchain` implementation simply because it is the only reference;
## once a formal Logos REST specification is available, that spec should become
## the authoritative source instead.
## Reference implementation:
## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs

const
  MANTLE_METRICS* = "/mantle/metrics"
  MANTLE_STATUS* = "/mantle/status"
  MANTLE_SDP_DECLARATIONS* = "/mantle/sdp/declarations"

  CRYPTARCHIA_INFO_PATH* = "/cryptarchia/info"
  CRYPTARCHIA_HEADERS* = "/cryptarchia/headers"
  CRYPTARCHIA_LIB_STREAM* = "/cryptarchia/lib-stream"

  NETWORK_INFO* = "/network/info"

  STORAGE_BLOCK* = "/storage/block"
  MEMPOOL_ADD_TX* = "/mempool/add/tx"

  SDP_POST_DECLARATION* = "/sdp/declaration"
  SDP_POST_ACTIVITY* = "/sdp/activity"
  SDP_POST_WITHDRAWAL* = "/sdp/withdrawal"

  LEADER_CLAIM_PATH* = "/leader/claim"

  BLOCKS* = "/cryptarchia/blocks"
  BLOCKS_STREAM* = "/cryptarchia/events/blocks/stream"

  WALLET_BALANCE_PATH* = "/wallet/{public_key}/balance"
  WALLET_TRANSACTIONS_TRANSFER_FUNDS_PATH* = "/wallet/transactions/transfer-funds"

  # Testing paths
  UPDATE_MEMBERSHIP* = "/test/membership/update"
