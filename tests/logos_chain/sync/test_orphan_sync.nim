# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  chronos/unittest2/asynctests,
  unittest2,
  results,
  libp2p/peerid,
  ../../../logos_chain/core/types,
  ../../../logos_chain/chain/[chain, block_processor, local_tree],
  ../../../logos_chain/sync/[syncer, orphan_sync],
  ./helpers,
  ../../testutil
from ../../../logos_chain/core/mantle/primitives import SlotNumber

suite "sync/orphan_sync (OrphanSync decision and lifecycle tests)":
  asyncTest "handleOrphan ignores orphan at or behind immutable slot":
    let
      genesis = createGenesisBlock(testValidGenesisTx())
      chain = initTestChain(genesis)
      bp = BlockProcessor.new(chain)
      syncer = Syncer.init(nil, bp, testChainSyncProtocol, nil)
      fakeParent = exampleBlockId(0x42)
      fakeOrphan = exampleBlockId(0x43)
    # Genesis slot is 0, latest immutable slot is 0
    check syncer.orphans.checkFetch(syncer.localTree, fakeParent, SlotNumber(0), Moment.now()).error ==
      OrphanError.BehindImmutable

    syncer.handleOrphan(fakeOrphan, fakeParent, SlotNumber(0))
    check syncer.orphans.activeDownloadCount == 0

  asyncTest "handleOrphan ignores orphan whose parent is already known":
    let
      genesis = createGenesisBlock(testValidGenesisTx())
      gid = blockId(genesis.header)
      chain = initTestChain(genesis)
      bp = BlockProcessor.new(chain)
      syncer = Syncer.init(nil, bp, testChainSyncProtocol, nil)
      fakeOrphan = exampleBlockId(0x43)
    # gid is already in localTree
    check syncer.orphans.checkFetch(syncer.localTree, gid, SlotNumber(10), Moment.now()).error ==
      OrphanError.ParentKnown

    syncer.handleOrphan(fakeOrphan, gid, SlotNumber(10))
    check syncer.orphans.activeDownloadCount == 0

  asyncTest "handleOrphan records cooldown when no candidate peers available":
    let
      genesis = createGenesisBlock(testValidGenesisTx())
      chain = initTestChain(genesis)
      bp = BlockProcessor.new(chain)
      syncer = Syncer.init(nil, bp, testChainSyncProtocol, nil)
      fakeParent = exampleBlockId(0x55)
      fakeOrphan = exampleBlockId(0x56)
    syncer.handleOrphan(fakeOrphan, fakeParent, SlotNumber(10))

    # Without peers, resolution immediately records cooldown
    check:
      waitUntil(syncer.orphans.isCoolingDown(fakeParent, Moment.now()), 1.seconds)
      syncer.orphans.checkFetch(syncer.localTree, fakeParent, SlotNumber(10), Moment.now()).error ==
        OrphanError.CoolingDown

    # Subsequent trigger while in cooldown is dropped
    syncer.handleOrphan(fakeOrphan, fakeParent, SlotNumber(10))
    check syncer.orphans.activeDownloadCount == 0

suite "sync/orphan_sync (end-to-end orphan resolution via DBR)":
  asyncTest "orphan block received over gossip triggers DBR, fetches parent, and promotes orphan":
    let
      genesis = createGenesisBlock(testValidGenesisTx())
      gid = blockId(genesis.header)
    var serverChain = initTestChain(genesis)
    let clientChain = initTestChain(genesis)

    # Server has: Genesis -> B1
    let
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
    check:
      serverChain.tryApplyBlock(b1).isOk
      serverChain.localTree.localTipId == b1id

    # Client only has: Genesis
    # Construct B2 (child of B1): Genesis -> B1 -> B2
    let
      b2 = childBlock(b1.header, b1id, SlotNumber(2), [])
      b2id = blockId(b2.header)

    withSyncPair(serverChain, clientChain):
      clientSyncer.peerProvider = proc(): seq[PeerId] =
        @[server.peerInfo.peerId]

      # Deliver orphan B2 to client processor (as if received over GossipSub)
      let
        p2 = Proposal(header: b2.header, references: default(References), signature: b2.signature)
        res = await clientSyncer.processor.addProposal(p2, b2id)
      check res.isErr and res.error.kind == BlockApplyErrorKind.OrphanBuffered

      # Client orphanSync automatically sends DBR for B1, applies B1, and promotes B2
      check:
        waitUntil(clientChain.localTree.hasBlock(b2id), 5.seconds)
        clientChain.localTree.localTipId == b2id
        clientChain.localTree.hasBlock(b1id)

{.pop.}
