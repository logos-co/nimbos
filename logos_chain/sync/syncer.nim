# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  chronicles,
  chronos,
  libp2p/[switch, peerid, errors],
  ../chain/chain,
  ../networking/network,
  ./[syncer_types, ibd_server, ibd_client, types]

export syncer_types

func init*(T: type Syncer, sw: Switch, chain: Chain, protocol: string): T =
  T(sw: sw, chain: chain, chainSyncProtocol: protocol)

proc runAtStartup(
    syncer: Syncer, syncPeers: seq[PeerId],
) {.async: (raises: [CancelledError]).} =
  try:
    mountCryptarchiaSyncHandler(syncer)
  except LPError as exc:
    fatal "Syncer start failed: failed to mount chain-sync handler",
      msg = exc.msg, protocol = syncer.chainSyncProtocol
    quit(QuitFailure)
  debug "Syncer started chain-sync handler",
    protocol = syncer.chainSyncProtocol,
    syncPeerCount = syncPeers.len
  if syncPeers.len > 0:
    try:
      await initialBlockDownload(syncer, syncPeers)
      notice "Syncer completed initial block download",
        peerCount = syncPeers.len,
        protocol = syncer.chainSyncProtocol
    except IBDFailure as exc:
      fatal "Syncer initial block download failed: unable to catch up with any IBD peer",
        msg = exc.msg, protocol = syncer.chainSyncProtocol
      quit(QuitFailure)

proc start*(syncer: Syncer, syncPeers: seq[PeerId] = @[]) =
  asyncSpawn syncer.runAtStartup(syncPeers)

{.pop.}
