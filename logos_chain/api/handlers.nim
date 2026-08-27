# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## NOTE: This module contains stub implementations for Logos HTTP API
## compatibility. The REST endpoints and many of their query parameters are
## currently **not** specified in any Logos Chain research/spec document. Where
## endpoint paths or parameter names matter, they currently follow the Rust
## `logos-blockchain` implementation simply because it is the only reference;
## once a formal Logos REST spec exists, it should become the authoritative
## source instead:
## https://github.com/logos-blockchain/logos-blockchain

import
  chronicles,
  libp2p/[multiaddress, multicodec],
  ../node,
  ../networking/[network, peer_pool],
  ./utils,
  ./paths

from presto/common import ContentBody

export utils

logScope: topics = "rest_node"

type
  ConnectionStateSet* = set[ConnectionState]
  PeerTypeSet* = set[PeerType]

  RestNodePeerCount* = object
    disconnected*: uint64
    connecting*: uint64
    connected*: uint64
    disconnecting*: uint64

RestJson.useDefaultSerializationFor(
  RestNodePeerCount,
)

proc normalize*(address: MultiAddress, value: PeerId): MaResult[MultiAddress] =
  ## Checks if `address` has `p2p` suffix, and if not add it.
  let
    protos = ? address.protocols()
    index = protos.find(multiCodec("p2p"))
  if index == -1:
    let suffix = ? MultiAddress.init(multiCodec("p2p"), value)
    concat(address, suffix)
  else:
    ok(address)

proc installNodeApiHandlers*(router: var RestRouter, node: LBNode) =
  ## -------------------------------------------------------------------
  ## Logos Chain HTTP API compatibility (stub implementations)
  ##
  ## These endpoints provide compatibility with the Logos HTTP API.
  ## The implementations are intentionally minimal and return empty payloads.
  ## NOTE: No written Logos Chain spec currently declares these REST endpoints.
  ## For now, query parameter naming follows the Rust `logos-blockchain`
  ## implementation (see handlers.rs) only because it is the only source;
  ## a future Logos REST spec should take precedence:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/node/binary/src/api/handlers.rs#L219
  ## -------------------------------------------------------------------

  # GET /cryptarchia/headers[?from={headerId}&to={headerId}]
  router.api2(MethodGet, CRYPTARCHIA_HEADERS) do (
    `from`: Option[HeaderId],
    `to`: Option[HeaderId],
  ) -> RestApiResponse:
    RestApiResponse.response("[]", Http200, $jsonMediaType)

  # GET /cryptarchia/lib/stream
  router.api2(MethodGet, CRYPTARCHIA_LIB_STREAM) do () -> RestApiResponse:
    RestApiResponse.response("", Http200, $jsonMediaType)

  # GET /cryptarchia/info
  router.api2(MethodGet, CRYPTARCHIA_INFO_PATH) do () -> RestApiResponse:
    RestApiResponse.response("{}", Http200, $jsonMediaType)

  # POST /leader/claim
  router.api2(MethodPost, LEADER_CLAIM_PATH) do () -> RestApiResponse:
    RestApiResponse.response("{}", Http200, $jsonMediaType)

  # GET /mantle/metrics
  router.api2(MethodGet, MANTLE_METRICS) do () -> RestApiResponse:
    RestApiResponse.response("{}", Http200, $jsonMediaType)

  # POST /mantle/status
  router.api2(MethodPost, MANTLE_STATUS) do (
    contentBody: Option[ContentBody],
  ) -> RestApiResponse:
    RestApiResponse.response("[]", Http200, $jsonMediaType)

  # POST /mempool/add/tx
  router.api2(MethodPost, MEMPOOL_ADD_TX) do (
    contentBody: Option[ContentBody],
  ) -> RestApiResponse:
    RestApiResponse.response("", Http200, $jsonMediaType)

  # GET /network/info
  router.api2(MethodGet, NETWORK_INFO) do () -> RestApiResponse:
    RestApiResponse.response("{}", Http200, $jsonMediaType)

  # POST /sdp/activity
  router.api2(MethodPost, SDP_POST_ACTIVITY) do (
    contentBody: Option[ContentBody],
  ) -> RestApiResponse:
    RestApiResponse.response("{}", Http200, $jsonMediaType)

  # POST /sdp/declaration
  router.api2(MethodPost, SDP_POST_DECLARATION) do (
    contentBody: Option[ContentBody],
  ) -> RestApiResponse:
    RestApiResponse.jsonResponse("")

  # POST /sdp/withdrawal
  router.api2(MethodPost, SDP_POST_WITHDRAWAL) do (
    contentBody: Option[ContentBody],
  ) -> RestApiResponse:
    RestApiResponse.response("{}", Http200, $jsonMediaType)

  # POST /storage/block
  router.api2(MethodPost, STORAGE_BLOCK) do (
    contentBody: Option[ContentBody],
  ) -> RestApiResponse:
    RestApiResponse.response("\"\"", Http200, $jsonMediaType)

  # POST /test/membership/update
  router.api2(MethodPost, UPDATE_MEMBERSHIP) do () -> RestApiResponse:
    RestApiResponse.response("{}", Http200, $jsonMediaType)

  # GET /wallet/{public_key}/balance[?tip={headerId}]
  router.api2(MethodGet, WALLET_BALANCE_PATH) do (
    `public_key`: utils.ZkPublicKey,
    tip: Option[HeaderId],
  ) -> RestApiResponse:
    RestApiResponse.response("{}", Http200, $jsonMediaType)

  # POST /wallet/transactions/transfer-funds
  router.api2(MethodPost, WALLET_TRANSACTIONS_TRANSFER_FUNDS_PATH) do (
    contentBody: Option[ContentBody],
  ) -> RestApiResponse:
    RestApiResponse.response("{}", Http200, $jsonMediaType)

  # GET /blocks[?slot_from={slotFrom}&slot_to={slotTo}]
  ## NOTE: No written Logos Chain spec currently declares this REST endpoint or its
  ## query parameter names. The `slot_from` / `slot_to` parameters follow the
  ## official `logos-blockchain` implementation, which defines
  ## `BlockRangeQuery { slot_from, slot_to }` in:
  ## https://github.com/logos-blockchain/logos-blockchain/blob/master/nodes/node/binary/src/api/queries.rs#L7
  router.api2(MethodGet, BLOCKS) do (
    slot_from: Option[uint64],
    slot_to: Option[uint64],
  ) -> RestApiResponse:
    RestApiResponse.response("[]", Http200, $jsonMediaType)

  # GET /blocks/stream
  router.api2(MethodGet, BLOCKS_STREAM) do () -> RestApiResponse:
    RestApiResponse.response("", Http200, $jsonMediaType)
