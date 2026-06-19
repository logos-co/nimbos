# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Types used by both client and server in the common REST API

import
  std/[json, tables],
  results,
  stew/base10, httputils

export tables, httputils, results

const
  # Maximum number of validators that can be served by the REST server in one
  # request, if the number of validator exceeds this value REST server
  # will return HTTP error 400.
  ServerMaximumValidatorIds* = 16384

  # Maximum number of validators that can be sent in single request by
  # validator client (VC).
  ClientMaximumValidatorIds* = 30

  # Maximum number of validator ids sent with validator client's duties
  # requests. Validator ids are sent in decimal encoding with comma, so
  # number of ids should not exceed beacon node's `rest-max-body-size`.
  DutiesMaximumValidatorIds* = 16384

type
  PeerStateKind* {.pure.} = enum
    Disconnected, Connecting, Connected, Disconnecting

  PeerDirectKind* {.pure.} = enum
    Inbound, Outbound

  RestNumeric* = distinct int

  RestIndexedErrorMessage* = object
    ## https://github.com/ethereum/beacon-APIs/blob/v2.4.0/types/http.yaml#L145
    code*: int
    message*: string
    failures*: seq[RestIndexedErrorMessageItem]

  RestIndexedErrorMessageItem* = object
    index*: int
    message*: string

  RestNodePeer* = object
    peer_id*: string
    enr*: string
    last_seen_p2p_address*: string
    state*: string
    direction*: string
    agent*: string # This is not part of specification
    proto*: string # This is not part of specification

  RestNodeVersion* = object
    version*: string

  RestSyncInfo* = object
    sync_distance*: uint64
    is_syncing*: bool
    is_optimistic*: Opt[bool]
    el_offline*: Opt[bool]

  RestPeerCount* = object
    disconnected*: uint64
    connecting*: uint64
    connected*: uint64
    disconnecting*: uint64

  RestChainHeadV2* = object
    execution_optimistic*: bool

  RestMetadata* = object
    seq_number*: string
    syncnets*: string
    attnets*: string
    custody_group_count*: string

  RestNetworkIdentity* = object
    peer_id*: string
    enr*: string
    p2p_addresses*: seq[string]
    discovery_addresses*: seq[string]
    metadata*: RestMetadata

  RestWithdrawalPrefix* = distinct array[1, byte]

  VCRuntimeConfig* = Table[string, string]

  DataEnclosedObject*[T] = object
    data*: T

  DataMetaEnclosedObject*[T] = object
    data*: T
    meta*: JsonNode

  DataVersionEnclosedObject*[T] = object
    data*: T
    version*: JsonNode

  DataRootEnclosedObject*[T] = object
    data*: T
    execution_optimistic*: Opt[bool]

  DataOptimisticObject*[T] = object
    data*: T
    execution_optimistic*: Opt[bool]

  DataOptimisticAndFinalizedObject*[T] = object
    data*: T
    execution_optimistic*: Opt[bool]
    finalized*: Opt[bool]

  ForkedSignedBlockHeader* = object
    message*: uint32 # message offset

  Web3SignerStatusResponse* = object
    status*: string

  RestNimbusTimestamp1* = object
    timestamp1*: uint64

  RestNimbusTimestamp2* = object
    timestamp1*: uint64
    timestamp2*: uint64
    timestamp3*: uint64
    delay*: uint64

  RestReward* = distinct int64

  GetDebugChainHeadsV2Response* = DataEnclosedObject[seq[RestChainHeadV2]]
  GetNetworkIdentityResponse* = DataEnclosedObject[RestNetworkIdentity]
  GetPeerCountResponse* = DataMetaEnclosedObject[RestPeerCount]
  GetPeerResponse* = DataMetaEnclosedObject[RestNodePeer]
  GetPeersResponse* = DataMetaEnclosedObject[seq[RestNodePeer]]
  GetSpecVCResponse* = DataEnclosedObject[VCRuntimeConfig]
  GetSyncingStatusResponse* = DataEnclosedObject[RestSyncInfo]
  GetVersionResponse* = DataEnclosedObject[RestNodeVersion]

  RestNode* = object
    weight*: uint64

  EmptyBody* = object
