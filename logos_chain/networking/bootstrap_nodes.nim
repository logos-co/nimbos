# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Bootstrap address parsing and file loader.
## Specs:
## - https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/draft/p2p-network.md#transport
## - https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/p2p-network-bootstrapping.md

{.push raises: [], gcsafe.}

import
  std/[sequtils, strutils],
  chronicles, results,
  libp2p/[peerid, peerinfo, multiaddress, multicodec],
  ../conf

const
  UdpCodec = multiCodec("udp")
  QuicCodec = multiCodec("quic-v1")

func parseBootstrapAddress*(address: string):
    Result[(PeerId, MultiAddress), string] =
  let trimmed = address.strip()
  if trimmed.len == 0:
    return err("Empty bootstrap address")
  if not trimmed.startsWith('/'):
    return err("Bootstrap address must be a libp2p multiaddr")

  let (peerId, baseAddr) = parseFullAddress(trimmed).valueOr:
    return err("Invalid bootstrap multiaddr: " & error)

  if not baseAddr.contains(UdpCodec).get(false):
    return err("Bootstrap multiaddr must include /udp")
  if not baseAddr.contains(QuicCodec).get(false):
    return err("Bootstrap multiaddr must include /quic-v1")

  ok((peerId, baseAddr))

iterator strippedLines(filename: string): string {.raises: [ref IOError].} =
  for line in lines(filename):
    let stripped = line.strip()
    if stripped.len > 0 and not stripped.startsWith('#'):
      yield stripped

proc addBootstrapNode(
    bootstrapAddr: string,
    bootstrapPeers: var seq[(PeerId, MultiAddress)]
) =
  let hashIdx = bootstrapAddr.find('#')
  let cleanAddr = (if hashIdx >= 0: bootstrapAddr[0 ..< hashIdx] else: bootstrapAddr).strip()
  if cleanAddr.len == 0:
    return

  let (peerId, baseAddr) = parseBootstrapAddress(cleanAddr).valueOr:
    warn "Ignoring invalid bootstrap address",
      bootstrapAddr, reason = error
    return

  if not bootstrapPeers.anyIt(it[0] == peerId):
    bootstrapPeers.add((peerId, baseAddr))

proc loadBootstrapFile(
    bootstrapFile: string,
    bootstrapPeers: var seq[(PeerId, MultiAddress)]
) =
  if bootstrapFile.len == 0: return
  try:
    for ln in strippedLines(bootstrapFile):
      addBootstrapNode(ln, bootstrapPeers)
  except IOError as e:
    error "Could not read bootstrap file", file = bootstrapFile, msg = e.msg

proc loadBootstrapNodes*(config: NetworkConfig): seq[(PeerId, MultiAddress)] =
  var bootstrapPeers: seq[(PeerId, MultiAddress)]
  for node in config.bootstrapNodes:
    addBootstrapNode(node, bootstrapPeers)
  loadBootstrapFile(string config.bootstrapNodesFile, bootstrapPeers)
  bootstrapPeers

{.pop.}
