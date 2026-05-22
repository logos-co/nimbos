# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import std/[os, strutils]
import unittest2
import stew/io2
import ../logos_chain/deployment/user_config

const testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]

const initialPeersFixturePath =
  testsDir / "fixtures/user_config-initial-peers.yaml"

const userConfigPath = testsDir / "../config/user_config.yaml"

suite "user-config initial_peers":
  test "parse initial_peers from fixture":
    let peers = loadUserConfigInitialPeers(initialPeersFixturePath).valueOr:
      raise newException(CatchableError, error)
    check peers.len == 2
    check peers[0].startsWith("/ip4/")
    check "/quic-v1/" in peers[0]
    check "/p2p/" in peers[0]

  test "missing initial_peers yields empty list":
    let peers = initialPeersFromYaml(parseUserConfigYaml("""
network:
  backend:
    swarm:
      host: 0.0.0.0
""").get).valueOr:
      raise newException(CatchableError, error)
    check peers.len == 0

  test "non-sequence initial_peers is rejected":
    let r = initialPeersFromYaml(parseUserConfigYaml("""
network:
  backend:
    initial_peers: /ip4/1.2.3.4/udp/3000/quic-v1/p2p/12D3KooW9wycYQTk8HPKHHyVzF2tUEpVSu4WHu8ySAbTmXGreuV5
""").get)
    check r.isErr
    check "initial_peers" in r.error

  test "parse canonical config/user_config.yaml when present":
    if not fileExists(userConfigPath):
      echo "skip: ", userConfigPath, " not found"
      return
    let peers = loadUserConfigInitialPeers(userConfigPath).valueOr:
      raise newException(CatchableError, error)
    check peers.len >= 1
    for p in peers:
      check p.startsWith("/")

{.pop.}
