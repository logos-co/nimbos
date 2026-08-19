# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Bootstrap address parsing and file loader.
## Specs:
## - https://github.com/logos-co/logos-lips/blob/master/docs/blockchain/draft/p2p-network.md#transport
## - https://github.com/logos-co/logos-lips/blob/master/docs/blockchain/raw/p2p-network-bootstrapping.md

{.push raises: [], gcsafe.}

import
  std/os,
  std/strutils,
  chronicles, results,
  libp2p/[peerid, peerinfo, multiaddress, multicodec],
  ../conf

func parseBootstrapAddress*(address: string):
    Result[(PeerId, MultiAddress), string] =
  let trimmed = address.strip()
  if trimmed.len == 0:
    return err("Empty bootstrap address")
  if not trimmed.startsWith("/"):
    return err("Bootstrap address must be a libp2p multiaddr")

  let parsed = parseFullAddress(trimmed)
  if parsed.isErr:
    return err("Invalid bootstrap multiaddr: " & parsed.error)

  let (peerId, baseAddr) = parsed.get()
  let protocols = baseAddr.protocols().valueOr:
    return err("Invalid bootstrap multiaddr protocols: " & error)

  if multiCodec("udp") notin protocols:
    return err("Bootstrap multiaddr must include /udp")
  if multiCodec("quic-v1") notin protocols:
    return err("Bootstrap multiaddr must include /quic-v1")

  ok((peerId, baseAddr))

iterator strippedLines(filename: string): string {.raises: [ref IOError].} =
  for line in lines(filename):
    let stripped = strip(line)
    if not stripped.startsWith('#') and stripped.len > 0:
      yield stripped

proc addBootstrapNode(
    bootstrapAddr: string,
    bootstrapPeers: var seq[(PeerId, MultiAddress)]
) =
  if bootstrapAddr.len == 0 or bootstrapAddr[0] == '#':
    return

  let addrRes = parseBootstrapAddress(bootstrapAddr.split(" # ")[0])
  if addrRes.isOk:
    bootstrapPeers.add addrRes.value
  else:
    warn "Ignoring invalid bootstrap address",
      bootstrapAddr, reason = addrRes.error

proc loadBootstrapFile(
    bootstrapFile: string,
    bootstrapPeers: var seq[(PeerId, MultiAddress)]
) =
  if bootstrapFile.len == 0: return
  let ext = splitFile(bootstrapFile).ext
  if cmpIgnoreCase(ext, ".txt") == 0:
    try:
      for ln in strippedLines(bootstrapFile):
        addBootstrapNode(ln, bootstrapPeers)
    except IOError as e:
      error "Could not read bootstrap file", msg = e.msg
      quit 1
  else:
    error "Unknown bootstrap file format", ext
    quit 1

proc loadBootstrapNodes*(config: NetworkConfig): seq[(PeerId, MultiAddress)] =
  var bootstrapPeers: seq[(PeerId, MultiAddress)]
  for node in config.bootstrapNodes:
    addBootstrapNode(node, bootstrapPeers)
  loadBootstrapFile(string config.bootstrapNodesFile, bootstrapPeers)
  bootstrapPeers

{.pop.}
