# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  chronicles, stew/base10, metrics,
  ../networking/lb_network

logScope:
  topics = "peer_proto"

type
  StatusMsg* = object
    e: uint64

  StatusMsgV2* = object
    e: uint64

  PeerSyncNetworkState* {.final.} = ref object of RootObj

  PeerSyncPeerState* {.final.} = ref object of RootObj
    statusLastTime: chronos.Moment
    statusMsg: StatusMsg
    statusMsgV2: Opt[StatusMsgV2]

declareCounter nbc_disconnects_count,
  "Number disconnected peers", labels = ["agent", "reason"]

func shortLog*(s: StatusMsg): auto =
  (
    e: $s.e
  )

func shortLog*(s: StatusMsgV2): auto =
  (
    e: $s.e
  )

proc getCurrentStatusV1(state: PeerSyncNetworkState): StatusMsg =
  StatusMsg()

proc getCurrentStatusV2(state: PeerSyncNetworkState): StatusMsgV2 =
  StatusMsgV2()

proc checkStatusMsg(state: PeerSyncNetworkState, status: StatusMsg | StatusMsgV2):
    Result[void, cstring] =
  ok()

proc handleStatusV1(peer: Peer,
                    state: PeerSyncNetworkState,
                    theirStatus: StatusMsg): Future[bool] {.async: (raises: [CancelledError]).}

proc setStatusV2Msg(state: PeerSyncPeerState,
                    statusMsg: Opt[StatusMsgV2]) =
  state.statusMsgV2 = statusMsg
  state.statusLastTime = Moment.now()

{.pop.} # TODO fix p2p macro for raises

p2pProtocol PeerSync(version = 1,
                       networkState = PeerSyncNetworkState,
                       peerState = PeerSyncPeerState):

  onPeerConnected do (peer: Peer, incoming: bool) {.
    async: (raises: [CancelledError]).}:
    debug "Peer connected", peer, peerId = shortLog(peer.peerId), incoming
    # Per the eth2 protocol, whoever dials must send a status message when
    # connected for the first time, but because of how libp2p works, there may
    # be a race between incoming and outgoing connections and disconnects that
    # makes the incoming flag unreliable / obsolete by the time we get to
    # this point - instead of making assumptions, we'll just send a status
    # message redundantly.
    let
      ourStatus = peer.networkState.getCurrentStatusV1()
      theirStatus =
        await peer.statusV1(ourStatus, timeout = RESP_TIMEOUT_DUR)

    if theirStatus.isOk:
      discard await peer.handleStatusV1(peer.networkState, theirStatus.get())
    else:
      debug "Status response not received in time",
            peer, errorKind = theirStatus.error.kind
      await peer.disconnect(FaultOrError)

  proc statusV1(peer: Peer,
                theirStatus: StatusMsg,
                response: SingleChunkResponse[StatusMsg])
      {.async, libp2pProtocol("status", 1).} =
    let ourStatus = peer.networkState.getCurrentStatusV1()
    trace "Sending status (v1)", peer = peer, status = ourStatus
    await response.send(ourStatus)
    discard await peer.handleStatusV1(peer.networkState, theirStatus)

  proc ping(peer: Peer, value: uint64): uint64
    {.libp2pProtocol("ping", 1).} = 0

  proc goodbye(peer: Peer, reason: uint64) {.
       async, libp2pProtocol("goodbye", 1).} =
    debug "Received Goodbye message"

proc setStatusMsg(peer: Peer, statusMsg: StatusMsg) =
  peer.state(PeerSync).statusMsg = statusMsg
  peer.state(PeerSync).statusLastTime = Moment.now()

proc setStatusV2Msg(peer: Peer, statusMsg: Opt[StatusMsgV2]) =
  peer.state(PeerSync).statusMsgV2 = statusMsg
  peer.state(PeerSync).statusLastTime = Moment.now()

proc handleStatusV1(peer: Peer,
                    state: PeerSyncNetworkState,
                    theirStatus: StatusMsg): Future[bool]
                    {.async: (raises: [CancelledError]).} =
  let
    res = checkStatusMsg(state, theirStatus)

  return if res.isErr():
    debug "Irrelevant peer", peer, theirStatus, err = res.error()
    await peer.disconnect(IrrelevantNetwork)
    false
  else:
    peer.setStatusMsg(theirStatus)

    if peer.connectionState == Connecting:
      # As soon as we get here it means that we passed handshake succesfully. So
      # we can add this peer to PeerPool.
      await peer.handlePeer()
    true

proc updateStatus*(peer: Peer): Future[bool] {.async: (raises: [CancelledError]).} =
  ## Request `status` of remote peer ``peer``.
  let nstate = peer.networkState(PeerSync)
  let
    ourStatus = getCurrentStatusV1(nstate)
    theirStatus =
      (await peer.statusV1(ourStatus, timeout = RESP_TIMEOUT_DUR)).valueOr:
        return false

  await peer.handleStatusV1(nstate, theirStatus)

proc getStatusLastTime*(peer: Peer): chronos.Moment =
  ## Returns head slot for specific peer ``peer``.
  peer.state(PeerSync).statusLastTime

proc init*(T: type PeerSync.NetworkState): T =
  T()
