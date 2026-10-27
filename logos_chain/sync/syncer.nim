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
  ../chain/block_processor,
  ./[syncer_types, sync_server, sync_client, orphan_sync, types]

export syncer_types, orphan_sync

proc init*(
    T: type Syncer,
    sw: Switch,
    processor: BlockProcessor,
    protocol: string,
    peerProvider: PeerProvider,
): T =
  T(
    sw: sw,
    processor: processor,
    chainSyncProtocol: protocol,
    peerProvider: peerProvider,
    orphans: OrphanSync.init(),
  )

proc runAtStartup(
    syncer: Syncer,
    onIbdComplete: OnIbdComplete,
    onIbdFailure: OnIbdFailure,
    bootstrapPeerProvider: PeerProvider,
) {.async: (raises: [CancelledError]).} =
  try:
    mountCryptarchiaSyncHandler(syncer)
  except LPError as exc:
    fatal "Syncer start failed: failed to mount chain-sync handler",
      msg = exc.msg, protocol = syncer.chainSyncProtocol
    if onIbdFailure != nil:
      onIbdFailure("Chain-sync handler mount failure: " & exc.msg)
    return
  debug "Syncer started chain-sync handler",
    protocol = syncer.chainSyncProtocol
  try:
    await initialBlockDownload(syncer, bootstrapPeerProvider)
    notice "Syncer completed initial block download",
      protocol = syncer.chainSyncProtocol
    if onIbdComplete != nil:
      onIbdComplete()
  except IBDFailure as exc:
    fatal "Syncer initial block download failed: unable to catch up with any IBD peer",
      msg = exc.msg, protocol = syncer.chainSyncProtocol
    if onIbdFailure != nil:
      onIbdFailure("Initial block download failure: " & exc.msg)
    return

proc start*(
    syncer: Syncer,
    onIbdComplete: OnIbdComplete,
    onIbdFailure: OnIbdFailure,
    bootstrapPeerProvider: PeerProvider = nil,
) =
  doAssert syncer.ibdFut == nil, "syncer already started"
  syncer.ibdFut = syncer.runAtStartup(onIbdComplete, onIbdFailure, bootstrapPeerProvider)

proc stop*(syncer: Syncer) {.async: (raises: []).} =
  ## Cancel orphan sync and initial block download if running.
  await syncer.stopOrphanSync()
  if syncer.ibdFut != nil:
    await syncer.ibdFut.cancelAndWait()
    syncer.ibdFut = nil

{.pop.}
