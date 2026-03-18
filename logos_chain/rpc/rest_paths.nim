# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

const
  ## NOTE: As of now there is no Nomos spec document that explicitly declares
  ## the `/mantle/metrics` HTTP endpoint. This path matches the official
  ## implementation in `logos-blockchain`:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  MANTLE_METRICS* = "/mantle/metrics"

  ## NOTE: As of now there is no Nomos spec document that explicitly declares
  ## a Mantle status HTTP endpoint. This path matches the official
  ## implementation in `logos-blockchain`:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  MANTLE_STATUS* = "/mantle/status"

  ## NOTE: The Service Declaration Protocol describes SDP declarations at a
  ## protocol level but does not define this concrete REST endpoint. The path
  ## value itself is taken from the official `logos-blockchain` implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  MANTLE_SDP_DECLARATIONS* = "/mantle/sdp/declarations"

  ## NOTE: Cryptarchia specs describe the chain but do not currently declare
  ## an `/cryptarchia/info` REST endpoint. This path value is aligned with the
  ## official `logos-blockchain` implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  CRYPTARCHIA_INFO_PATH* = "/cryptarchia/info"

  ## NOTE: Cryptarchia specs describe headers but do not currently declare
  ## a `/cryptarchia/headers` REST endpoint. This path value is aligned with
  ## the official `logos-blockchain` implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  CRYPTARCHIA_HEADERS* = "/cryptarchia/headers"

  ## NOTE: Cryptarchia bootstrapping/sync specs discuss streaming but there is
  ## no concrete `/cryptarchia/lib-stream` REST endpoint declared in the specs.
  ## This path value is aligned with the official `logos-blockchain`
  ## implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  CRYPTARCHIA_LIB_STREAM* = "/cryptarchia/lib-stream"

  ## NOTE: The P2P and Bedrock specs define node/network information but do
  ## not declare a `/network/info` HTTP endpoint. This path value is aligned
  ## with the official `logos-blockchain` implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  NETWORK_INFO* = "/network/info"

  ## NOTE: Bedrock block specs define block formats but do not currently
  ## specify a `/storage/block` REST endpoint. This path value is aligned
  ## with the official `logos-blockchain` implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  STORAGE_BLOCK* = "/storage/block"

  ## NOTE: Mantle and block specs cover transactions and mempools, but there
  ## is no explicit `/mempool/add/tx` REST endpoint in the specs at this time.
  ## This path value is aligned with the official `logos-blockchain`
  ## implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  MEMPOOL_ADD_TX* = "/mempool/add/tx"

  ## NOTE: The Service Declaration Protocol does not currently define a
  ## concrete `/sdp/declaration` REST endpoint. This path value is aligned
  ## with the official `logos-blockchain` implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  SDP_POST_DECLARATION* = "/sdp/declaration"

  ## NOTE: Service Reward Distribution specs discuss activity reporting but do
  ## not declare a `/sdp/activity` REST endpoint yet. This path value is
  ## aligned with the official `logos-blockchain` implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  SDP_POST_ACTIVITY* = "/sdp/activity"

  ## NOTE: Service Reward Distribution specs cover withdrawals but do not
  ## define a `/sdp/withdrawal` HTTP endpoint in the text of the spec. This
  ## path value is aligned with the official `logos-blockchain`
  ## implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  SDP_POST_WITHDRAWAL* = "/sdp/withdrawal"

  ## NOTE: Bedrock specs describe leader election but do not declare a
  ## concrete `/leader/claim` REST endpoint. This path value is aligned
  ## with the official `logos-blockchain` implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  LEADER_CLAIM* = "/leader/claim"

  ## NOTE: Cryptarchia specs define blocks but there is no explicit
  ## `/cryptarchia/blocks` REST endpoint in the specs. This path value is
  ## aligned with the official `logos-blockchain` implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  BLOCKS* = "/cryptarchia/blocks"

  ## NOTE: Cryptarchia synchronization specs describe block streams
  ## conceptually, but do not define a
  ## `/cryptarchia/events/blocks/stream` REST endpoint. This path value is
  ## aligned with the official `logos-blockchain` implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  BLOCKS_STREAM* = "/cryptarchia/events/blocks/stream"

  ## NOTE: The Wallet Technical Standard specifies address and balance
  ## semantics, but does not currently define a `/wallet/{public_key}/balance`
  ## HTTP endpoint. This route is an implementation of those concepts and its
  ## path shape matches the official `logos-blockchain` implementation (which
  ## uses a `:public_key` parameter):
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  WALLET_BALANCE_PATH* = "/wallet/{public_key}/balance"

  ## NOTE: The Wallet Technical Standard defines transfer semantics but does
  ## not declare a `/wallet/transactions/transfer-funds` REST endpoint. This
  ## route is implementation-defined based on that spec and matches the
  ## official `logos-blockchain` implementation:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/api-common/src/paths.rs
  WALLET_TRANSACTIONS_TRANSFER_FUNDS_PATH* = "/wallet/transactions/transfer-funds"

  # Testing paths
  UPDATE_MEMBERSHIP* = "/test/membership/update"