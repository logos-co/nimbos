# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  chronos,
  libp2p/[switch, peerid],
  ../chain/block_processor

type
  PeerProvider* = proc(): seq[PeerId] {.gcsafe, raises: [].}

  Syncer* = ref object
    sw*: Switch
    processor*: BlockProcessor
    chainSyncProtocol*: string
    ibdFut*: Future[void].Raising([CancelledError])

template localTree*(syncer: Syncer): LocalTree = syncer.processor.chain.localTree

{.pop.}
