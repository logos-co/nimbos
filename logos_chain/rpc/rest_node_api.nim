# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## NOTE: This module contains stub implementations for Logos HTTP API
## compatibility. The REST endpoints and many of their query parameters are
## currently **not** specified in any Nomos research/spec document. Where
## endpoint paths or parameter names matter, they currently follow the Rust
## `logos-blockchain` implementation simply because it is the only reference;
## once a formal Logos REST spec exists, it should become the authoritative
## source instead:
## https://github.com/logos-blockchain/logos-blockchain

import
  chronicles,
  eth/enr/enr,
  libp2p/[multiaddress, multicodec, peerstore],
  ../version, ../logos_chain_node,
  ../networking/[eth2_network, peer_pool],
  ../spec/datatypes/base,
  ./rest_utils,
  ./rest_paths

from presto/common import ContentBody

export rest_utils

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

proc validateState(states: seq[PeerStateKind]): Result[ConnectionStateSet,
                                                       cstring] =
  var res: set[ConnectionState]
  for item in states:
    case item
    of PeerStateKind.Disconnected:
      if ConnectionState.Disconnected in res:
        return err("Peer connection states must be unique")
      res.incl(ConnectionState.Disconnected)
    of PeerStateKind.Connecting:
      if ConnectionState.Connecting in res:
        return err("Peer connection states must be unique")
      res.incl(ConnectionState.Connecting)
    of PeerStateKind.Connected:
      if ConnectionState.Connected in res:
        return err("Peer connection states must be unique")
      res.incl(ConnectionState.Connected)
    of PeerStateKind.Disconnecting:
      if ConnectionState.Disconnecting in res:
        return err("Peer connection states must be unique")
      res.incl(ConnectionState.Disconnecting)
  if res == {}:
    res = {ConnectionState.Connecting, ConnectionState.Connected,
           ConnectionState.Disconnecting, ConnectionState.Disconnected}
  ok(res)

proc validateDirection(directions: seq[PeerDirectKind]): Result[PeerTypeSet,
                                                                cstring] =
  var res: set[PeerType]
  for item in directions:
    case item
    of PeerDirectKind.Inbound:
      if PeerType.Incoming in res:
        return err("Peer direction states must be unique")
      res.incl(PeerType.Incoming)
    of PeerDirectKind.Outbound:
      if PeerType.Outgoing in res:
        return err("Peer direction states must be unique")
      res.incl(PeerType.Outgoing)
  if res == {}:
    res = {PeerType.Incoming, PeerType.Outgoing}
  ok(res)

proc toString(state: ConnectionState): string =
  case state
  of ConnectionState.Disconnected:
    "disconnected"
  of ConnectionState.Connecting:
    "connecting"
  of ConnectionState.Connected:
    "connected"
  of ConnectionState.Disconnecting:
    "disconnecting"
  else:
    ""

proc toString(direction: PeerType): string =
  case direction:
  of PeerType.Incoming:
    "inbound"
  of PeerType.Outgoing:
    "outbound"

proc getLastSeenAddress(node: LBNode, id: PeerId): string =
  let
    address = node.network.switch.peerStore[LastSeenBook][id].valueOr:
      return ""
    normalized = address.normalize(id).valueOr:
      return ""
  $normalized

proc getDiscoveryAddresses(node: LBNode): seq[string] =
  let
    typedRec = TypedRecord.fromRecord(node.network.enrRecord())
    peerAddr = typedRec.toPeerAddr(udpProtocol).valueOr:
      return default(seq[string])
    maddress = MultiAddress.init(multiCodec("p2p"), peerAddr.peerId).valueOr:
      return default(seq[string])

  var addresses: seq[string]
  for item in peerAddr.addrs:
    let res = concat(item, maddress)
    if res.isOk():
      addresses.add($(res.get()))
  addresses

proc getP2PAddresses(node: LBNode): seq[string] =
  let
    pinfo = node.network.switch.peerInfo
    maddress = MultiAddress.init(multiCodec("p2p"), pinfo.peerId).valueOr:
      return default(seq[string])

  var addresses: seq[string]
  for item in node.network.announcedAddresses:
    let res = concat(item, maddress)
    if res.isOk():
      addresses.add($(res.get()))
  for item in pinfo.addrs:
    let res = concat(item, maddress)
    if res.isOk():
      addresses.add($(res.get()))
  addresses

proc installNodeApiHandlers*(router: var RestRouter, node: LBNode) =
  let
    cachedVersion =
      RestApiResponse.prepareJsonResponse((version: nimbusAgentStr))

  ## -------------------------------------------------------------------
  ## Logos Chain HTTP API compatibility (stub implementations)
  ##
  ## These endpoints provide compatibility with the Logos HTTP API.
  ## The implementations are intentionally minimal and return empty payloads.
  ## NOTE: No written Nomos spec currently declares these REST endpoints.
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
  router.api2(MethodPost, LEADER_CLAIM) do () -> RestApiResponse:
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
    `public_key`: ZkPublicKey,
    tip: Option[HeaderId],
  ) -> RestApiResponse:
    RestApiResponse.response("{}", Http200, $jsonMediaType)

  # POST /wallet/transactions/transfer-funds
  router.api2(MethodPost, WALLET_TRANSACTIONS_TRANSFER_FUNDS_PATH) do (
    contentBody: Option[ContentBody],
  ) -> RestApiResponse:
    RestApiResponse.response("{}", Http200, $jsonMediaType)

  # GET /blocks[?slot_from={slotFrom}&slot_to={slotTo}]
  ## NOTE: No written Nomos spec currently declares this REST endpoint or its
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
