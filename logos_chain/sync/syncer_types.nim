# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  std/tables,
  chronos,
  libp2p/[switch, peerid],
  ../chain/block_processor

type
  PeerProvider* = proc(): seq[PeerId] {.gcsafe, raises: [].}
  OnIbdComplete* = proc() {.gcsafe, raises: [].}
  OnIbdFailure* = proc(reason: string) {.gcsafe, raises: [].}

  OrphanFetch* = object
    attempts*: int
    lastAttempt*: Moment

  OrphanSync = object
    active*: Table[BlockId, Future[void]]
    retries*: Table[BlockId, OrphanFetch]
    triedPeers*: Table[BlockId, seq[PeerId]]

  Syncer* = ref object
    sw*: Switch
    processor*: BlockProcessor
    chainSyncProtocol*: string
    ibdFut*: Future[void].Raising([CancelledError])
    orphanLoopFut*: Future[void].Raising([CancelledError])
    peerProvider*: PeerProvider
    orphans*: OrphanSync

template localTree*(syncer: Syncer): LocalTree = syncer.processor.localTree
template orphanPool*(syncer: Syncer): OrphanPool = syncer.processor.orphanPool

{.pop.}
