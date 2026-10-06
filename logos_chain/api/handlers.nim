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
## endpoint paths or parameter names matter, they currently follow the
## `logos-blockchain` reference implementation simply because it is the only
## reference; once a formal Logos REST spec exists, it should become the
## authoritative source instead:
## https://github.com/logos-blockchain/logos-blockchain

import
  std/sequtils,
  chronicles,
  faststreams/textio,
  libp2p/[multiaddress, multicodec, switch],
  ../node,
  ../core/local_tree,
  ../networking/[libp2p_json_serialization, network, peer_pool],
  ./[paths, utils]

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

  RestU64* = distinct uint64
    ## JSON number; the default ``uint64`` writer emits a quoted string.
  RestHeaderId* = distinct Hash32
    ## Lowercase hex with no ``0x`` prefix.

  RestConsensusState* {.pure.} = enum
    Bootstrapping
    Online

  RestChainPhase* {.pure.} = enum
    AwaitingGenesisTime
    InitialBlockDownload
    ProlongedBootstrapPeriod
    Following

  RestCryptarchiaInfo* = object
    lib*: RestHeaderId
    lib_slot*: RestU64
    tip*: RestHeaderId
    slot*: RestU64
    height*: RestU64
    state*: RestConsensusState

  RestChainServiceInfo* = object
    cryptarchia_info*: RestCryptarchiaInfo
    phase*: RestChainPhase

  RestNetworkInfo* = object
    listen_addresses*: seq[MultiAddress]
    peer_id*: PeerId
    connected_peers*: seq[PeerId]
    n_peers*: RestU64
    n_connections*: RestU64
    n_pending_connections*: RestU64
    discovered_peers*: seq[PeerId]
    n_discovered_peers*: RestU64

proc writeValue*(
    w: var JsonWriter[RestJson], value: RestU64) {.raises: [IOError].} =
  w.streamElement(s):
    s.writeText(uint64(value))

proc writeValue*(
    w: var JsonWriter[RestJson], value: RestHeaderId) {.raises: [IOError].} =
  w.streamElement(s):
    s.write('"')
    s.writeHex(Hash32(value))
    s.write('"')

RestJson.useDefaultSerializationFor(
  RestChainServiceInfo,
  RestCryptarchiaInfo,
  RestNetworkInfo,
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

func cryptarchiaInfo*(localTree: LocalTree): RestChainServiceInfo =
  ## Local tip and latest immutable block of ``localTree``.
  let tip = localTree.localTip()
  # The bootstrap FSM is not implemented yet. Thus the state and the phase
  # are constants.
  RestChainServiceInfo(
    cryptarchia_info: RestCryptarchiaInfo(
      lib: RestHeaderId(localTree.latestImmutableBlockId),
      lib_slot: RestU64(localTree.latestImmutableSlot),
      tip: RestHeaderId(tip.tip),
      slot: RestU64(tip.slot),
      height: RestU64(tip.height),
      state: RestConsensusState.Online,
    ),
    phase: RestChainPhase.Following,
  )

proc networkInfo*(network: LBP2PNode): RestNetworkInfo =
  ## Addresses, established connections, and discovered peers of ``network``.
  let
    connections = network.switch.connManager.getConnections()
    discovered = discoveredPeers(network.mountedProtocols.kad, network.switch)
  RestNetworkInfo(
    listen_addresses: network.listenAddresses(),
    peer_id: network.peerId,
    connected_peers: toSeq(connections.keys),
    n_peers: RestU64(connections.len),
    n_connections: RestU64(toSeq(connections.values).foldl(a + b.len, 0)),
    n_pending_connections: RestU64(network.pendingDialCount()),
    discovered_peers: discovered,
    n_discovered_peers: RestU64(discovered.len),
  )

proc installNodeApiHandlers*(router: var RestRouter, node: LBNode) =
  ## -------------------------------------------------------------------
  ## Logos Chain HTTP API compatibility (stub implementations)
  ##
  ## These endpoints provide compatibility with the Logos HTTP API.
  ## Most implementations are stubs that return empty payloads.
  ## NOTE: No written Logos Chain spec currently declares these REST endpoints.
  ## For now, query parameter naming follows the `logos-blockchain` reference
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
    if node.isNil or node.processor.isNil or node.processor.localTree.isNil:
      return RestApiResponse.jsonError(Http503, ChainNotReadyError)
    RestApiResponse.jsonResponsePlain(cryptarchiaInfo(node.processor.localTree))

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
    if node.isNil or node.network.isNil:
      return RestApiResponse.jsonError(Http503, NetworkNotReadyError)
    RestApiResponse.jsonResponsePlain(networkInfo(node.network))

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

{.pop.}
