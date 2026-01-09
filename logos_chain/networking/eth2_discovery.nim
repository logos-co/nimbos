# nimbos
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[algorithm, sequtils],
  chronos, chronicles,
  eth/p2p/discoveryv5/[protocol, node, random2],
  ../spec/eth2_ssz_serialization,
  ".."/[conf]

from std/os import splitFile
from std/strutils import cmpIgnoreCase, split, startsWith, strip, toLowerAscii

export protocol, node

type
  Eth2DiscoveryProtocol* = protocol.Protocol
  Eth2DiscoveryId* = NodeId

const udpPort* = 5000.Port

func parseBootstrapAddress*(address: string):
    Result[enr.Record, string] =
  let lowerCaseAddress = toLowerAscii(address)
  if lowerCaseAddress.startsWith("enr:"):
    let res = enr.Record.fromURI(address)
    if res.isOk():
      return ok res.value
    return err "Invalid bootstrap ENR: " & $res.error
  elif lowerCaseAddress.startsWith("enode:"):
    return err "ENode bootstrap addresses are not supported"
  else:
    return err "Ignoring unrecognized bootstrap address type"

iterator strippedLines(filename: string): string {.raises: [ref IOError].} =
  for line in lines(filename):
    let stripped = strip(line)
    if stripped.startsWith('#'): # Comments
      continue

    if stripped.len > 0:
      yield stripped

proc addBootstrapNode*(bootstrapAddr: string,
                       bootstrapEnrs: var seq[enr.Record]) =
  # Ignore empty lines or lines starting with #
  if bootstrapAddr.len == 0 or bootstrapAddr[0] == '#':
    return

  # Ignore comments in
  # https://github.com/eth-clients/mainnet/blob/main/metadata/bootstrap_nodes.txt
  let enrRes = parseBootstrapAddress(bootstrapAddr.split(" # ")[0])
  if enrRes.isOk:
    bootstrapEnrs.add enrRes.value
  else:
    warn "Ignoring invalid bootstrap address",
          bootstrapAddr, reason = enrRes.error

proc loadBootstrapFile*(bootstrapFile: string,
                        bootstrapEnrs: var seq[enr.Record]) =
  if bootstrapFile.len == 0: return
  let ext = splitFile(bootstrapFile).ext
  if cmpIgnoreCase(ext, ".txt") == 0 or cmpIgnoreCase(ext, ".enr") == 0 :
    try:
      for ln in strippedLines(bootstrapFile):
        addBootstrapNode(ln, bootstrapEnrs)
    except IOError as e:
      error "Could not read bootstrap file", msg = e.msg
      quit 1
  else:
    error "Unknown bootstrap file format", ext
    quit 1

proc new*(T: type Eth2DiscoveryProtocol,
          config: BeaconNodeConf,
          enrIp: Opt[IpAddress], enrTcpPort, enrUdpPort: Opt[Port],
          pk: PrivateKey,
          rng: ref HmacDrbgContext):
          T =
  # TODO
  # Implement more configuration options:
  # * for setting up a specific key
  # * for using a persistent database
  var bootstrapEnrs: seq[enr.Record]
  for node in config.bootstrapNodes:
    addBootstrapNode(node, bootstrapEnrs)
  loadBootstrapFile(string config.bootstrapNodesFile, bootstrapEnrs)

  let listenAddress =
    if config.listenAddress.isSome():
      Opt.some(config.listenAddress.get())
    else:
      Opt.none(IpAddress)

  newProtocol(pk, enrIp, enrTcpPort, enrUdpPort, @[], bootstrapEnrs,
    bindPort = udpPort, bindIp = listenAddress,
    enrAutoUpdate = config.enrAutoUpdate, rng = rng)

proc queryRandom*(
    d: Eth2DiscoveryProtocol,
    minScore: int): Future[seq[Node]] {.async: (raises: [CancelledError]).} =
  ## Perform a discovery query for a random target
  let nodes = await d.queryRandom()

  var filtered: seq[(int, Node)]
  for n in nodes:
    filtered.add((0, n))

  d.rng[].shuffle(filtered)
  return filtered.sortedByIt(-it[0]).mapIt(it[1])
