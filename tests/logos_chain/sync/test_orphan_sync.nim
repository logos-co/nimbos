# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/tables,
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

proc initTestSyncer(peers: seq[PeerId] = @[]): Syncer =
  let
    genesis = createGenesisBlock(testValidGenesisTx())
    chain = initTestChain(genesis)
    bp = BlockProcessor.new(chain)
    provider = if peers.len > 0: (proc(): seq[PeerId] = peers) else: nil
  Syncer.init(nil, bp, testChainSyncProtocol, provider)

suite "sync/orphan_sync (OrphanSync decision and lifecycle tests)":
  asyncTest "fetchParent records failure when no candidate peers available":
    let
      syncer = initTestSyncer()
      fakeParent = exampleBlockId(0x55)
      child = mkAdmittedBlock(2, fakeParent)

    check:
      syncer.orphanPool.addOrphan(child)
      syncer.orphanPool.isMissingParent(fakeParent)
      syncer.orphans.retries.getOrDefault(fakeParent).attempts == 0

    await syncer.fetchParent(fakeParent)
    check:
      syncer.orphans.retries.getOrDefault(fakeParent).attempts == 1
      syncer.orphans.active.len == 0

  test "nextPeer rotates untried candidate peers across attempts":
    let
      peer1 = getRandomPeerId()
      peer2 = getRandomPeerId()
      syncer = initTestSyncer(@[peer1, peer2])
      fakeParent = exampleBlockId(0x66)

    check:
      # Attempt 1: picks peer1
      syncer.nextPeer(fakeParent).get == peer1
      # Attempt 2: filters peer1, picks peer2
      syncer.nextPeer(fakeParent).get == peer2
      # Attempt 3: all tried, resets round to peer1
      syncer.nextPeer(fakeParent).get == peer1

  test "retry failure backoff progression and descendant eviction":
    let
      syncer = initTestSyncer()
      parentId = exampleBlockId(1)
      b1 = mkAdmittedBlock(2, parentId)
      b1Id = blockId(b1.header)
      b2 = mkAdmittedBlock(3, b1Id)
      b2Id = blockId(b2.header)
      t0 = Moment.now()

    check:
      syncer.orphanPool.addOrphan(b1)
      syncer.orphanPool.addOrphan(b2)
      not syncer.isCoolingDown(parentId, t0)

    # Failure 1 -> 1s backoff
    syncer.recordFailure(parentId, t0)
    check:
      syncer.orphans.retries.getOrDefault(parentId).attempts == 1
      syncer.isCoolingDown(parentId, t0 + 500.milliseconds)
      syncer.nextBackoffDuration(t0 + 500.milliseconds).get == 500.milliseconds
      not syncer.isCoolingDown(parentId, t0 + 1000.milliseconds)

    # Failure 2 -> still waiting
    syncer.recordFailure(parentId, t0 + 1000.milliseconds)
    check syncer.orphanPool.isMissingParent(parentId)

    # Failure 3 (MaxOrphanRetries) -> purges parent, descendant orphans, and retry state
    syncer.recordFailure(parentId, t0 + 2000.milliseconds)
    check:
      not syncer.orphanPool.isMissingParent(parentId)
      syncer.orphanPool.len == 0
      not syncer.orphanPool.hasOrphan(b1Id)
      not syncer.orphanPool.hasOrphan(b2Id)
      parentId notin syncer.orphans.retries

suite "sync/orphan_sync (end-to-end orphan resolution via DBR)":
  asyncTest "orphan block received over gossip triggers DBR, fetches parent, and promotes orphan":
    let
      genesis = createGenesisBlock(testValidGenesisTx())
      gid = blockId(genesis.header)
      clientChain = initTestChain(genesis)
      # Server has: Genesis -> B1
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      b1id = blockId(b1.header)
      # Client only has: Genesis; construct B2 (child of B1): Genesis -> B1 -> B2
      b2 = childBlock(b1.header, b1id, SlotNumber(2), [])
      b2id = blockId(b2.header)
    var serverChain = initTestChain(genesis)

    check:
      serverChain.tryApplyBlock(b1).isOk
      serverChain.localTree.localTipId == b1id

    withSyncPair(serverChain, clientChain):
      clientSyncer.peerProvider = proc(): seq[PeerId] =
        @[server.peerInfo.peerId]

      # Deliver orphan B2 to client processor (as if received over GossipSub)
      let
        p2 = Proposal(header: b2.header, references: default(References), signature: b2.signature)
        res = await clientSyncer.processor.addProposal(p2, b2id)
      check:
        res.error.kind == BlockApplyErrorKind.OrphanBuffered
        # Client orphanSync automatically sends DBR for B1, applies B1, and promotes B2
        waitUntil(clientChain.localTree.hasBlock(b2id), 5.seconds)
        clientChain.localTree.localTipId == b2id
        clientChain.localTree.hasBlock(b1id)

{.pop.}
