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
    syncer: Syncer, bootstrapPeerIds: seq[PeerId],
) {.async: (raises: [CancelledError]).} =
  if bootstrapPeerIds.len > 0:
    if not await waitForBootstrapConnectivity(syncer.sw, bootstrapPeerIds):
      warn "Syncer start skipped: bootstrap peer not connected",
        protocol = syncer.chainSyncProtocol
      return
  try:
    mountCryptarchiaSyncHandler(syncer)
  except LPError as exc:
    warn "Syncer start skipped: failed to mount chain-sync handler",
      msg = exc.msg, protocol = syncer.chainSyncProtocol
    return
  debug "Syncer started chain-sync handler",
    protocol = syncer.chainSyncProtocol,
    bootstrapPeerCount = bootstrapPeerIds.len
  try:
    await initialBlockDownload(syncer, bootstrapPeerIds)
    notice "Syncer completed initial block download",
      peerCount = bootstrapPeerIds.len,
      protocol = syncer.chainSyncProtocol
  except IBDFailure as exc:
    warn "Syncer initial block download failed",
      msg = exc.msg, protocol = syncer.chainSyncProtocol

proc start*(syncer: Syncer, bootstrapPeerIds: seq[PeerId]) =
  asyncSpawn syncer.runAtStartup(bootstrapPeerIds)

{.pop.}
