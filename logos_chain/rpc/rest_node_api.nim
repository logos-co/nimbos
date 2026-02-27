# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronicles,
  eth/enr/enr,
  libp2p/[multiaddress, multicodec, peerstore],
  ../version, ../logos_chain_node,
  ../networking/[eth2_network, peer_pool],
  ../spec/datatypes/base,
  ./rest_utils

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

## --- Logos HTTP API stub types (used by `node_http_client_api.nim`) ---

type
  ## Mirrors `CryptarchiaMode` from `node_http_client_api.nim`
  LogosRpcCryptarchiaMode* = enum
    lrcBootstrapping
    lrcOnline

  ## Mirrors `CryptarchiaInfo` from `node_http_client_api.nim`
  LogosRpcCryptarchiaInfo* = object
    lib*: string
    tip*: string
    slot*: uint64
    height*: uint64
    mode*: LogosRpcCryptarchiaMode

  ## Minimal wallet balance body
  LogosRpcWalletBalance* = object
    balance*: string

  ## Minimal transfer-funds response body
  LogosRpcTransferFundsResponse* = object
    txHash*: string

RestJson.useDefaultSerializationFor(
  LogosRpcCryptarchiaInfo,
  LogosRpcWalletBalance,
  LogosRpcTransferFundsResponse,
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

proc getLastSeenAddress(node: BeaconNode, id: PeerId): string =
  let
    address = node.network.switch.peerStore[LastSeenBook][id].valueOr:
      return ""
    normalized = address.normalize(id).valueOr:
      return ""
  $normalized

proc getDiscoveryAddresses(node: BeaconNode): seq[string] =
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

proc getP2PAddresses(node: BeaconNode): seq[string] =
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

proc installNodeApiHandlers*(router: var RestRouter, node: BeaconNode) =
  let
    cachedVersion =
      RestApiResponse.prepareJsonResponse((version: nimbusAgentStr))

  ## -------------------------------------------------------------------
  ## Logos HTTP API compatibility (stub implementations)
  ##
  ## These endpoints are provided so that the Nim client in
  ## `node_http_client_api.nim` can talk to this node using the same
  ## paths as the Rust `CommonHttpClient`. The implementations are
  ## intentionally minimal and return placeholder data.
  ## -------------------------------------------------------------------

  # GET /cryptarchia/blocks?slot_from={slotFrom}&slot_to={slotTo}
  router.api2(MethodGet, "/cryptarchia/blocks") do () -> RestApiResponse:
    ## Stub: return an empty list of blocks.
    let blocks: seq[string] = @[]
    RestApiResponse.jsonResponse(blocks)

  # GET /cryptarchia/headers[?from={headerId}&to={headerId}]
  router.api2(MethodGet, "/cryptarchia/headers") do (
    from: Option[string],
    to_: Option[string],
  ) -> RestApiResponse:
    ## Stub: return empty list of headers.
    discard from, to_
    RestApiResponse.response("[]", Http200, jsonMediaType)

  # GET /cryptarchia/info
  router.api2(MethodGet, "/cryptarchia/info") do () -> RestApiResponse:
    let info = LogosRpcCryptarchiaInfo(
      lib: "",
      tip: "",
      slot: 0'u64,
      height: 0'u64,
      mode: LogosRpcCryptarchiaMode.lrcBootstrapping,
    )
    RestApiResponse.jsonResponse(info)

  # POST /leader/claim
  router.api2(MethodPost, "/leader/claim") do () -> RestApiResponse:
    ## Stub: return empty JSON.
    RestApiResponse.response("{}", Http200, jsonMediaType)

  # GET /mantle/metrics
  router.api2(MethodGet, "/mantle/metrics") do () -> RestApiResponse:
    ## Stub: return empty JSON metrics.
    RestApiResponse.response("{}", Http200, jsonMediaType)

  # GET /mantle/sdp/declarations
  router.api2(MethodGet, "/mantle/sdp/declarations") do () -> RestApiResponse:
    ## Stub: return empty JSON list.
    RestApiResponse.response("[]", Http200, jsonMediaType)

  # POST /mantle/status
  router.api2(MethodPost, "/mantle/status") do (
    body: ContentBody,
  ) -> RestApiResponse:
    ## Stub: accept status payload and return empty JSON.
    discard body.strData
    RestApiResponse.response("{}", Http200, jsonMediaType)

  # POST /mempool/add/tx
  router.api2(MethodPost, "/mempool/add/tx") do (body: ContentBody) -> RestApiResponse:
    ## Stub: accept the transaction payload but do nothing with it.
    discard body.strData
    RestApiResponse.response("", Http200, jsonMediaType)

  # GET /network/info
  router.api2(MethodGet, "/network/info") do () -> RestApiResponse:
    ## Stub: return empty JSON object.
    RestApiResponse.response("{}", Http200, jsonMediaType)

  # POST /sdp/activity
  router.api2(MethodPost, "/sdp/activity") do (
    body: ContentBody,
  ) -> RestApiResponse:
    ## Stub: accept activity and return empty JSON.
    discard body.strData
    RestApiResponse.response("{}", Http200, jsonMediaType)

  # POST /sdp/declaration
  router.api2(MethodPost, "/sdp/declaration") do (
    body: ContentBody,
  ) -> RestApiResponse:
    ## Stub: accept declaration and return empty JSON.
    discard body.strData
    RestApiResponse.response("{}", Http200, jsonMediaType)

  # POST /sdp/withdrawal
  router.api2(MethodPost, "/sdp/withdrawal") do (
    body: ContentBody,
  ) -> RestApiResponse:
    ## Stub: accept withdrawal and return empty JSON.
    discard body.strData
    RestApiResponse.response("{}", Http200, jsonMediaType)

  # POST /storage/block
  router.api2(MethodPost, "/storage/block") do (body: ContentBody) -> RestApiResponse:
    ## Stub: no blocks are available from this node.
    discard body.strData
    RestApiResponse.jsonError(Http404, BlocksUnavailable)

  # POST /test/membership/update
  router.api2(MethodPost, "/test/membership/update") do (
    body: ContentBody,
  ) -> RestApiResponse:
    ## Stub: accept membership update and return empty JSON.
    discard body.strData
    RestApiResponse.response("{}", Http200, jsonMediaType)

  # GET /wallet/{public_key}/balance[?tip={headerId}]
  router.api2(MethodGet, "/wallet/{public_key}/balance") do (
    public_key: string,
    tip: Option[string],
  ) -> RestApiResponse:
    ## Stub: always return balance "0".
    let body = LogosRpcWalletBalance(balance: "0")
    RestApiResponse.jsonResponse(body)

  # POST /wallet/transactions/transfer-funds
  router.api2(MethodPost, "/wallet/transactions/transfer-funds") do (
    body: ContentBody,
  ) -> RestApiResponse:
    ## Stub: accept request and return a dummy transaction hash.
    discard body.strData
    let resp = LogosRpcTransferFundsResponse(txHash: "0x0")
    RestApiResponse.jsonResponse(resp)


