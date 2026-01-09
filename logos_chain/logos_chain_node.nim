# nimbos
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/osproc,

  # Nimble packages
  chronos, presto, presto/server, bearssl/rand,
  metrics, metrics/chronos_httpserver,

  # Local modules
  "."/conf,
  ./networking/eth2_network,
  ./spec/datatypes/base

export
  osproc, chronos, presto, server, conf,
  eth2_network, base

type
  BeaconNode* = ref object
    network*: Eth2Node
    netKeys*: NetKeyPair
    config*: BeaconNodeConf
    restServer*: RestServerRef
    metricsServer*: Opt[MetricsHttpServerRef]
    shutdownEvent*: AsyncEvent

# TODO https://github.com/status-im/nim-stew/pull/258
template findIt*(s: openArray, predicate: untyped): int =
  var res = -1
  for i, it {.inject.} in s:
    if predicate:
      res = i
      break
  res

template rng*(node: BeaconNode): ref HmacDrbgContext =
  node.network.rng

func hasRestAllowedOrigin*(node: BeaconNode): bool =
  node.config.restAllowedOrigin.isSome
