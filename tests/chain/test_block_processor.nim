# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/sequtils,
  chronos,
  chronos/unittest2/asynctests,
  unittest2,
  results,
  stew/byteutils,
  libp2p/crypto/ed25519/ed25519,
  libp2p/protocols/pubsub/pubsub,
  ../testutil,
  ../logos_chain/sync/helpers,
  ../../logos_chain/chain/block_processor,
  ../../logos_chain/chain/gossip_processor

template addBlock(
    bp: BlockProcessor, blk: Block
): BlockApplyFuture =
  bp.addBlock(blk, blockId(header(blk)))

template addProposalBlock(
    bp: BlockProcessor, proposal: Proposal
): BlockApplyFuture =
  bp.addProposalBlock(
    admitProposal(proposal, bp.mempool).expect("proposal admits"),
    blockId(proposal.header))

proc initZeroFeeTestChain(genesis: ValidBlock): Chain =
  ## Test chain whose genesis state charges no fees, so a block can carry txs.
  var chain = initTestChain(genesis)
  let gid = blockId(genesis.header)
  var s = chain.ledger.state(gid).get()
  s.feeMarket.executionBaseFee = 0
  s.feeMarket.storageGasPrice = 0
  chain.ledger.commitUpdate(gid, s)
  chain

suite "chain/block_processor":
  setup:
    let
      genesisBlk = createGenesisBlock(testValidGenesisTx())
      gid = blockId(genesisBlk.header)
      chain = initTestChain(genesisBlk)

  asyncTest "addBlock applies a child of genesis and completes ok":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        r = await bp.addBlock(b1)
      check:
        r.isOk
        bp.localTree.localTipId == blockId(b1.header)
        bp.ledger.state(blockId(b1.header)).isSome

  asyncTest "addBlock on an applied block completes with AlreadyApplied":
    withProcessor(chain):
      let b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
      check (await bp.addBlock(b1)).isOk
      let r = await bp.addBlock(b1)
      check r.isErr and r.error.kind == BlockApplyErrorKind.AlreadyApplied

  asyncTest "addBlock on a buffered orphan completes immediately with OrphanAlreadyBuffered":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        b2 = childBlock(b1.header, blockId(b1.header), SlotNumber(2), [])
      # Buffer b2 as orphan
      check:
        (await bp.addBlock(b2)).error.kind == BlockApplyErrorKind.OrphanBuffered
        chain.orphanPool.hasOrphan(blockId(b2.header))
      # Ingesting duplicate b2 while in orphanPool returns OrphanAlreadyBuffered immediately
      let fDup = bp.addBlock(b2)
      check:
        fDup.finished
        (await fDup).error.kind == BlockApplyErrorKind.OrphanAlreadyBuffered

  asyncTest "buffering an orphan triggers bp.orphanEvent only for gossip source":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        b2 = childBlock(b1.header, blockId(b1.header), SlotNumber(2), [])
        b3 = childBlock(b2.header, blockId(b2.header), SlotNumber(3), [])
        p2 = Proposal(header: b2.header, references: default(References), signature: b2.signature)

      check:
        # Non-gossip source (Sync) buffers orphan without triggering orphanEvent
        not bp.orphanEvent.isSet
        (await bp.addBlock(b3)).error.kind == BlockApplyErrorKind.OrphanBuffered
        not bp.orphanEvent.isSet
        # Gossip source buffers orphan and triggers orphanEvent
        (await bp.addProposalBlock(p2)).error.kind == BlockApplyErrorKind.OrphanBuffered
        bp.orphanEvent.isSet

  asyncTest "addBlock deduplicates in-flight blocks immediately":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        f1 = bp.addBlock(b1)
        f2 = bp.addBlock(b1)
      check:
        f2.finished
        (await f2).error.kind == BlockApplyErrorKind.InFlight
        (await f1).isOk

  test "inFlightKey distinguishes variations in R, S, and BlockId":
    let
      b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
      id2 = blockId(genesisBlk.header)
    var
      sigR = b1.signature
      sigS = b1.signature
    sigR.data[10] = sigR.data[10] xor 0xaa'u8
    sigS.data[42] = sigS.data[42] xor 0x55'u8

    let keyBase = inFlightKey(id1, b1.signature)
    let keyR = inFlightKey(id1, sigR)
    let keyS = inFlightKey(id1, sigS)
    let keyId2 = inFlightKey(id2, b1.signature)

    check keyBase != keyR
    check keyBase != keyS
    check keyR != keyS
    check keyBase != keyId2

  asyncTest "addBlock with different signatures for the same header do not lock each other out":
    withProcessor(chain):
      # 1. Tamper R-half (byte index < 32)
      var badB1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
      badB1.signature.data[0] = badB1.signature.data[0] xor 0xff'u8
      let fBad = bp.addBlock(badB1)

      # 2. Tamper S-half (byte index >= 32)
      var badB1_S = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
      badB1_S.signature.data[45] = badB1_S.signature.data[45] xor 0xff'u8
      let fBad_S = bp.addBlock(badB1_S)

      # 3. Legitimate block with valid signature is queued without InFlight collision
      let goodB1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
      let id1 = blockId(goodB1.header)
      check bp.checkDeduplication(id1, badB1.signature).error == BlockApplyErrorKind.InFlight
      check bp.checkDeduplication(id1, badB1_S.signature).error == BlockApplyErrorKind.InFlight
      check bp.checkDeduplication(id1, goodB1.signature).isOk

      let fGood = bp.addBlock(goodB1)

      check (await fBad).error.kind == BlockApplyErrorKind.InvalidStructure
      check (await fBad_S).error.kind == BlockApplyErrorKind.InvalidStructure
      check (await fGood).isOk
      check bp.localTree.localTipId == id1

  asyncTest "queue is FIFO":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        b2 = childBlock(b1.header, blockId(b1.header), SlotNumber(2), [])
        f2 = bp.addBlock(b2)
        f1 = bp.addBlock(b1)
      check not f1.finished
      check not f2.finished
      check (await f2).error.kind == BlockApplyErrorKind.OrphanBuffered
      check (await f1).isOk
      # b2 is promoted asynchronously across event-loop turns
      check waitUntil(bp.localTree.hasBlock(blockId(b2.header)))
      check bp.localTree.localTipId == blockId(b2.header)
      check (await bp.addBlock(b2)).error.kind == BlockApplyErrorKind.AlreadyApplied

  asyncTest "orphan cascade yields cooperatively between each promoted orphan":
    withProcessor(chain):
      var
        blocks = newSeqOfCap[Block](6)
        parentHdr = genesisBlk.header
        parentId = gid
      for slot in 1 .. 6:
        let blk = childBlock(parentHdr, parentId, SlotNumber(slot), [])
        blocks.add blk
        parentHdr = blk.header
        parentId = blockId(blk.header)

      # Buffer blocks 2..5 as orphans first
      for i in 1 .. 5:
        check (await bp.addBlock(blocks[i])).error.kind ==
          BlockApplyErrorKind.OrphanBuffered
      check chain.orphanPool.len == 5

      # Start background ticker to count event loop yields
      var ticksWhileBusy = 0
      let lastId = blockId(blocks[5].header)
      proc ticker() {.async: (raises: [CancelledError]).} =
        while true:
          await sleepAsync(0.milliseconds)
          if not bp.localTree.hasBlock(lastId):
            inc ticksWhileBusy
      let tickerFut = ticker()

      # Ingest parent block 0 -> triggers cascade promotion of blocks 1..5
      check (await bp.addBlock(blocks[0])).isOk

      # Wait for all orphans to be promoted
      check waitUntil(bp.localTree.hasBlock(lastId))

      await tickerFut.cancelAndWait()
      for b in blocks:
        check bp.localTree.hasBlock(blockId(b.header))
      check bp.localTree.localTipId == lastId
      check chain.orphanPool.len == 0
      # Verify cooperative yielding occurred between orphan promotions
      check ticksWhileBusy >= 4

  asyncTest "failing promoted orphan prunes waiting descendants asynchronously":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(2), [])
        id1 = blockId(b1.header)
        # b2 has slot 2 == parent slot 2 -> passes stateless checks, but fails on promotion
        b2 = childBlock(b1.header, id1, SlotNumber(2), [])
        id2 = blockId(b2.header)
        b3 = childBlock(b2.header, id2, SlotNumber(3), [])
        id3 = blockId(b3.header)
        b4 = childBlock(b3.header, id3, SlotNumber(4), [])
        id4 = blockId(b4.header)

      # Buffer b4, b3, b2 as orphans
      check (await bp.addBlock(b4)).error.kind == BlockApplyErrorKind.OrphanBuffered
      check (await bp.addBlock(b3)).error.kind == BlockApplyErrorKind.OrphanBuffered
      check (await bp.addBlock(b2)).error.kind == BlockApplyErrorKind.OrphanBuffered
      check chain.orphanPool.len == 3

      # Ingest parent b1 -> triggers promotion of b2 which fails and prunes b3, b4
      check (await bp.addBlock(b1)).isOk

      # Allow event loop to process the promoted orphan failure and prune descendants
      check waitUntil(chain.orphanPool.len == 0)

      check bp.localTree.hasBlock(id1)
      check not bp.localTree.hasBlock(id2)
      check not bp.localTree.hasBlock(id3)
      check not bp.localTree.hasBlock(id4)

  asyncTest "loop yields to other tasks between blocks":
    withProcessor(chain):
      var
        blocks = newSeqOfCap[Block](16)
        parentHdr = genesisBlk.header
        parentId = gid
      for slot in 1 .. 16:
        let blk = childBlock(parentHdr, parentId, SlotNumber(slot), [])
        blocks.add blk
        parentHdr = blk.header
        parentId = blockId(blk.header)

      # `popFirst` on a non-empty queue returns a finished future, and `await`
      # on a finished future does not return to `poll`. Without the `idleAsync`
      # line the whole queue drains inside one callback and the ticker never
      # runs while results are pending. With it, each poll pass promotes one
      # idler after due timers, so the ticker fires at least once per block
      # and in practice about every second poll pass. Expect a count near 23.
      let futs = blocks.mapIt(bp.addBlock(it))
      var ticksWhileBusy = 0
      proc ticker() {.async: (raises: [CancelledError]).} =
        while true:
          await sleepAsync(0.milliseconds)
          if not futs.allIt(it.finished):
            inc ticksWhileBusy
      let tickerFut = ticker()

      await allFutures(futs)
      await tickerFut.cancelAndWait()
      check futs.allIt(it.read().isOk)
      check ticksWhileBusy >= blocks.len - 1

  asyncTest "a rejected block does not stall the loop":
    withProcessor(chain):
      var fakeParentId: BlockId
      fakeParentId[0] = 7
      let
        orphan = childBlock(genesisBlk.header, fakeParentId, SlotNumber(1), [])
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
      discard bp.addBlock(orphan)
      check (await bp.addBlock(b1)).isOk
      check not bp.localTree.hasBlock(blockId(orphan.header))

  asyncTest "error kinds: OrphanBuffered and InvalidStructure":
    withProcessor(chain):
      var fakeParentId: BlockId
      fakeParentId[0] = 7
      let
        orphan = childBlock(genesisBlk.header, fakeParentId, SlotNumber(1), [])
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        # Same slot as its parent, but above the LIB slot so the fork gate
        # does not fire first.
        stale = childBlock(b1.header, blockId(b1.header), SlotNumber(1), [])
      check (await bp.addBlock(orphan)).error.kind ==
        BlockApplyErrorKind.OrphanBuffered
      check (await bp.addBlock(b1)).isOk
      check (await bp.addBlock(stale)).error.kind ==
        BlockApplyErrorKind.InvalidStructure

  asyncTest "addProposalBlock applies an admitted child of genesis":
    withProcessor(chain):
      let
        b1 = childValidBlock(genesisBlk.header, gid, SlotNumber(1), [])
        p1 = Proposal(header: b1.header, references: default(References), signature: b1.signature)
        r = await bp.addProposalBlock(p1)
      check r.isOk
      check bp.localTree.localTipId == blockId(p1.header)
      check bp.ledger.state(blockId(p1.header)).isSome

  asyncTest "processProposal ignores an unresolved reference without taking an in-flight slot":
    # Guard: the only test that maps an unresolved reference to Ignore.
    withProcessor(chain):
      let
        p = childProposal(genesisBlk.header, gid, SlotNumber(1), [minimalValidSignedTx()])
        id = blockId(p.header)
      check:
        bp.processProposal(p, getRandomPeerId()) == ValidationResult.Ignore
        bp.checkDeduplication(id, p.signature).isOk

  asyncTest "an admitted proposal applies after its transaction leaves the mempool":
    # Guard: apply uses the transactions that the gate resolved. A second
    # mempool read would miss the removed transaction.
    let zeroFeeChain = initZeroFeeTestChain(genesisBlk)
    withProcessor(zeroFeeChain):
      let
        tx = validSignedTxWithOps(1, 1)
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        p = childProposal(b1.header, blockId(b1.header), SlotNumber(2), [tx])
        id = blockId(p.header)
      check:
        (await bp.addBlock(b1)).isOk
        bp.mempool.add(tx, SlotNumber(0))
      let admittedBlk = admitProposal(p, bp.mempool).expect("proposal admits")
      bp.mempool.remove(tx.hash, moveToGrace = false)
      check:
        (await bp.addProposalBlock(admittedBlk, id)).isOk
        bp.localTree.localTipId == id

  asyncTest "processProposal rejects a body over MaxBlockSize":
    withProcessor(chain):
      let
        tx = createValidTxForTest(mkSizedTx(MaxBlockSize + 1))
        p = childProposal(genesisBlk.header, gid, SlotNumber(1), [tx])
      check:
        bp.mempool.add(tx, SlotNumber(0))
        bp.processProposal(p, getRandomPeerId()) == ValidationResult.Reject
        bp.checkDeduplication(blockId(p.header), p.signature).isOk

  asyncTest "processProposal rejects a zero parent above slot 0":
    withProcessor(chain):
      let p = childProposal(genesisBlk.header, default(BlockId), SlotNumber(1), [])
      check bp.processProposal(p, getRandomPeerId()) == ValidationResult.Reject

  asyncTest "processProposal rejects a small-order leader key":
    # Under the identity key, R = B and S = 1 verify for every message.
    withProcessor(chain):
      var p = childProposal(genesisBlk.header, gid, SlotNumber(1), [])
      p.header.proofOfLeadership.leaderKey =
        EdPublicKey(data: hexToByteArray[32](
          "0100000000000000000000000000000000000000000000000000000000000000"))
      p.signature = EdSignature(data: hexToByteArray[64](
        "5866666666666666666666666666666666666666666666666666666666666666" &
        "0100000000000000000000000000000000000000000000000000000000000000"))
      check:
        verify_signature(p.header, p.signature)
        bp.processProposal(p, getRandomPeerId()) == ValidationResult.Reject

  asyncTest "stop ends the loop and cancels later addBlock calls":
    withProcessor(chain):
      check bp.running
      await bp.stop()
      check not bp.running
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        f = bp.addBlock(b1)
      check waitUntil(f.cancelled())

  asyncTest "cascaded orphan promotions apply multiple levels of buffered orphans":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        id1 = blockId(b1.header)
        b2 = childBlock(b1.header, id1, SlotNumber(2), [])
        id2 = blockId(b2.header)
        b3 = childBlock(b2.header, id2, SlotNumber(3), [])
        id3 = blockId(b3.header)

      # Queue b2 and b3 as orphans
      let f3 = bp.addBlock(b3)
      let f2 = bp.addBlock(b2)
      check (await f3).error.kind == BlockApplyErrorKind.OrphanBuffered
      check (await f2).error.kind == BlockApplyErrorKind.OrphanBuffered

      # Ingest root b1
      let f1 = bp.addBlock(b1)
      check (await f1).isOk

      # Both b2 and b3 are promoted and applied
      check waitUntil(bp.localTree.hasBlock(id3))

      check bp.localTree.hasBlock(id1)
      check bp.localTree.hasBlock(id2)
      check bp.localTree.hasBlock(id3)
      check chain.orphanPool.len == 0

  asyncTest "promoted orphan supersedes pending raw incoming block in queue and fulfills its future":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        id1 = blockId(b1.header)
        b2 = childBlock(b1.header, id1, SlotNumber(2), [])
        id2 = blockId(b2.header)

      # 1. Queue b1 first (it sits at front of queue)
      let f1 = bp.addBlock(b1)

      # 2. Queue raw b2 next (it sits behind b1 in queue as RawIncoming)
      let fRawB2 = bp.addBlock(b2)
      check not fRawB2.finished

      # 3. Buffer admitted copy of b2 in orphanPool before b1 finishes processing
      let status = checkTopology(b2.header, bp.localTree, bp.ledger).get()
      let admittedB2 = admitBlock(b2).get()
      check status == TopologyStatus.Orphan
      check chain.orphanPool.addOrphan(admittedB2)

      # 4. Awaiting f1 allows event loop to process b1, which promotes admittedB2 from orphanPool.
      # The promoted orphan supersedes the queued raw b2, steals fRawB2, and applies.
      check (await f1).isOk

      # 5. The stolen caller future fRawB2 completes with ok()
      let resRawB2 = await fRawB2
      check resRawB2.isOk

      check bp.localTree.hasBlock(id1)
      check bp.localTree.hasBlock(id2)
      check chain.orphanPool.len == 0

  asyncTest "promoted orphan failing validation completes stolen caller future with error":
    withProcessor(chain):
      let
        b1 = childBlock(genesisBlk.header, gid, SlotNumber(2), [])
        id1 = blockId(b1.header)
        # b2 has slot 2 == parent b1 slot 2 -> passes Tiers 0-2 (isOrphan), but fails Tier 3 on promotion
        b2 = childBlock(b1.header, id1, SlotNumber(2), [])
        id2 = blockId(b2.header)

      let f1 = bp.addBlock(b1)
      let fRawB2 = bp.addBlock(b2)
      check not fRawB2.finished

      let status = checkTopology(b2.header, bp.localTree, bp.ledger).get()
      let admittedB2 = admitBlock(b2).get()
      check status == TopologyStatus.Orphan
      check chain.orphanPool.addOrphan(admittedB2)

      check (await f1).isOk

      # Promoted b2 fails validation and completes the stolen future fRawB2 with an error
      let resRawB2 = await fRawB2
      check resRawB2.isErr
      check not bp.localTree.hasBlock(id2)
      check chain.orphanPool.len == 0

  asyncTest "processProposal with tampered references rejects and does not suppress genuine proposal":
    withProcessor(chain):
      let
        b = childValidBlock(genesisBlk.header, gid, SlotNumber(1), [])
        p = Proposal(header: b.header, references: default(References), signature: b.signature)
        id = blockId(p.header)
        peer = getRandomPeerId()
        sm = minimalValidSignedTx()

      check bp.mempool.add(sm, SlotNumber(0))
      var pBad = p
      pBad.references = References(@[txReference(sm.hash)])

      # 1. pBad is rejected immediately at gossip gate
      check bp.processProposal(pBad, peer) == ValidationResult.Reject

      # 2. In-flight / dedup table was not polluted
      check bp.checkDeduplication(id, p.signature).isOk

      # 3. Genuine proposal is accepted at gossip gate and applied
      check bp.processProposal(p, peer) == ValidationResult.Accept
      await sleepAsync(50.millis)
      check bp.localTree.localTipId == id

  asyncTest "processProposal with tampered uncle headers rejects and does not suppress genuine proposal":
    withProcessor(chain):
      let
        b = childValidBlock(genesisBlk.header, gid, SlotNumber(1), [])
        p = Proposal(header: b.header, references: default(References), signature: b.signature)
        id = blockId(p.header)
        peer = getRandomPeerId()

      var pBad = p
      var uHdr: Header
      uHdr.bedrockVersion = ExpectedBedrockVersion
      pBad.uncleHeaders = UncleHeaders(@[SignedHeader(header: uHdr, signature: default(Ed25519Signature))])

      check bp.processProposal(pBad, peer) == ValidationResult.Reject
      check bp.checkDeduplication(id, p.signature).isOk

      check bp.processProposal(p, peer) == ValidationResult.Accept
      await sleepAsync(50.millis)
      check bp.localTree.localTipId == id

  asyncTest "addBlock with tampered txs does not suppress a genuine copy":
    withProcessor(chain):
      let
        b = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
        id = blockId(b.header)

      var bBad = b
      bBad.txs = BlockTxs(@[minimalHashedSignedTx()])

      let badFut = bp.addBlock(bBad, id)
      check badFut.completed
      check badFut.value.isErr
      check badFut.value.error.kind == BlockApplyErrorKind.InvalidStructure

      check bp.checkDeduplication(id, b.signature).isOk

      let goodFut = bp.addBlock(b, id)
      check (await goodFut).isOk
      check bp.localTree.localTipId == id

  asyncTest "processProposal rejects a bad signature before resolving references":
    # Guard: the signature check runs before the mempool step. The tx is not
    # in the mempool, so without that check the verdict would be Ignore.
    withProcessor(chain):
      var p = childProposal(genesisBlk.header, gid, SlotNumber(1), [minimalValidSignedTx()])
      p.signature.data[0] = p.signature.data[0] xor 1
      check bp.processProposal(p, getRandomPeerId()) == ValidationResult.Reject

{.pop.}
