# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

## Spec: [Cryptarchia Bootstrapping & Synchronization](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/cryptarchia-v1-bootstr-sync.md)

{.push raises: [], gcsafe.}

import
  chronicles,
  chronos,
  results,
  libp2p/[switch, peerid, errors],
  ../chain/block_processor,
  ./[syncer_types, ibd_server, ibd_client, types]

export syncer_types

func init*(
    T: type Syncer, sw: Switch, processor: BlockProcessor, protocol: string): T =
  T(sw: sw, processor: processor, chainSyncProtocol: protocol)

proc runAtStartup(
    syncer: Syncer,
    onIbdComplete: OnIbdComplete,
    peerProvider: Opt[PeerProvider],
    onIbdFailure: OnIbdFailure,
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
    await initialBlockDownload(syncer, peerProvider)
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
    peerProvider: Opt[PeerProvider] = Opt.none(PeerProvider),
) =
  doAssert syncer.ibdFut == nil, "syncer already started"
  syncer.ibdFut = syncer.runAtStartup(onIbdComplete, peerProvider, onIbdFailure)

proc stop*(syncer: Syncer) {.async: (raises: []).} =
  ## Cancel the initial block download if running.
  if syncer.ibdFut != nil:
    await syncer.ibdFut.cancelAndWait()
    syncer.ibdFut = nil

{.pop.}
