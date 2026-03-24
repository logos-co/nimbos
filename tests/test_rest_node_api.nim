# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import std/strutils
import chronos, chronos/apps, chronos/unittest2/asynctests
import presto/[route, server]
import ./helpers
import ../logos_chain/rpc/rest_paths
import ../logos_chain/rpc/rest_node_api
from ../logos_chain/nimbus_binary_common import validateBeaconApiQueries

suite "Logos REST node API stub endpoints":
  var
    server: RestServerRef
    address: TransportAddress

  block:
    let serverAddress = initTAddress("127.0.0.1:0")
    var router = RestRouter.init(validateBeaconApiQueries)
    router.installNodeApiHandlers(nil) # BeaconNode is nil for stubs

    let sres = RestServerRef.new(router, serverAddress)
    server = sres.get()
    server.start()
    address = server.localAddress()

  asyncTest "GET /cryptarchia/headers returns empty list":
    let res = await httpClient(address, MethodGet, CRYPTARCHIA_HEADERS, "")
    check res.status == 200
    check res.data == "[]"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /cryptarchia/lib-stream returns empty body":
    let res = await httpClient(address, MethodGet, CRYPTARCHIA_LIB_STREAM, "")
    check res.status == 200
    check res.data.len == 0
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /cryptarchia/info returns empty object":
    let res = await httpClient(address, MethodGet, CRYPTARCHIA_INFO_PATH, "")
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /leader/claim returns empty object":
    let res = await httpClient(address, MethodPost, LEADER_CLAIM, "")
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /mantle/metrics returns empty object":
    let res = await httpClient(address, MethodGet, MANTLE_METRICS, "")
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /mantle/status returns empty list":
    let res =
      await httpClient(address, MethodPost, MANTLE_STATUS, "{}", "application/json")
    check res.status == 200
    check res.data == "[]"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /mempool/add/tx returns empty body":
    let res =
      await httpClient(address, MethodPost, MEMPOOL_ADD_TX, "{}", "application/json")
    check res.status == 200
    check res.data.len == 0
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /network/info returns empty object":
    let res = await httpClient(address, MethodGet, NETWORK_INFO, "")
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /sdp/activity returns empty list":
    let res =
      await httpClient(address, MethodPost, SDP_POST_ACTIVITY, "{}", "application/json")
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /sdp/declaration returns wrapped empty string":
    let res = await httpClient(
      address, MethodPost, SDP_POST_DECLARATION, "{}", "application/json"
    )
    check res.status == 200
    check res.data == """{"data":""}"""
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /sdp/withdrawal returns empty object":
    let res = await httpClient(
      address, MethodPost, SDP_POST_WITHDRAWAL, "{}", "application/json"
    )
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /storage/block returns empty quoted string":
    let res =
      await httpClient(address, MethodPost, STORAGE_BLOCK, "{}", "application/json")
    check res.status == 200
    check res.data == "\"\""
    check res.headers.getString("content-type") == "application/json"

  asyncTest "POST /test/membership/update returns empty object":
    let res = await httpClient(address, MethodPost, UPDATE_MEMBERSHIP, "")
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /wallet/{public_key}/balance returns empty object":
    let dummyKey = "0".repeat(64)
    let walletPath = WALLET_BALANCE_PATH.replace("{public_key}", dummyKey)
    let res = await httpClient(address, MethodGet, walletPath, "")
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /wallet/{public_key}/balance rejects invalid public_key":
    let badKey = "not-hex"
    let walletPath = WALLET_BALANCE_PATH.replace("{public_key}", badKey)
    let res = await httpClient(address, MethodGet, walletPath, "")
    check res.status == 404

  asyncTest "validateBeaconApiQueries accepts valid wallet public_key with and without 0x":
    let key = "0".repeat(64)
    check validateBeaconApiQueries("{public_key}", key) == 0
    check validateBeaconApiQueries("{public_key}", "0x" & key) == 0

  asyncTest "validateBeaconApiQueries rejects invalid wallet public_key lengths and characters":
    check validateBeaconApiQueries("{public_key}", "0".repeat(63)) == 1
    check validateBeaconApiQueries("{public_key}", "0".repeat(65)) == 1
    check validateBeaconApiQueries("{public_key}", "g".repeat(64)) == 1

  asyncTest "POST /wallet/transactions/transfer-funds returns empty object":
    let res = await httpClient(
      address, MethodPost, WALLET_TRANSACTIONS_TRANSFER_FUNDS_PATH, "{}",
      "application/json",
    )
    check res.status == 200
    check res.data == "{}"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /cryptarchia/blocks returns empty list":
    let res = await httpClient(address, MethodGet, BLOCKS, "")
    check res.status == 200
    check res.data == "[]"
    check res.headers.getString("content-type") == "application/json"

  asyncTest "GET /cryptarchia/events/blocks/stream returns empty body":
    let res = await httpClient(address, MethodGet, BLOCKS_STREAM, "")
    check res.status == 200
    check res.data.len == 0
    check res.headers.getString("content-type") == "application/json"
