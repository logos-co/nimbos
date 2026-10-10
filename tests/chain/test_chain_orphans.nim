# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/times,
  ../testutil,
  ../logos_chain/sync/helpers,
  ../../logos_chain/chain/chain

proc setupChain(
    securityParam: uint64 = 10'u64,
): tuple[chain: Chain, genesis: Block, gid: BlockId] =
  let
    genesis = createGenesisBlock(SignedMantleTx(testGenesisTx())).get
    gid = blockId(genesis.header)
  var c = initTestChain(genesis, securityParam = securityParam)
  c.slotConfig.genesisTime = uint64(getTime().toUnix() - 500)
  var s = c.ledger.state(gid).get()
  s.feeMarket.executionBaseFee = 0
  s.feeMarket.storageGasPrice = 0
  c.ledger.commitUpdate(gid, s)
  (c, genesis, gid)

proc syncApplyBlock(chain: var Chain, blk: Block): Result[void, BlockApplyError] =
  ?chain.tryApplyBlock(blk)
  var
    queue = chain.orphanPool.takeChildren(blockId(blk.header))
    idx = 0
  while idx < queue.len:
    let child = queue[idx]
    inc idx
    let res = chain.tryApplyAdmittedBlock(child)
    if res.isOk:
      queue.add(chain.orphanPool.takeChildren(blockId(child.header)))
  ok()

suite "chain/orphan_resolution":
  test "buffers out-of-order block and promotes it when parent arrives":
    var (chain, genesis, gid) = setupChain()

    let
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, SlotNumber(2), [])
      id2 = blockId(b2.header)
      # 1. Ingest child B2 before parent B1
      applyB2Res = chain.tryApplyBlock(b2)
    check:
      applyB2Res.isErr
      applyB2Res.error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.orphanPool.hasOrphan(id2)
      not chain.localTree.hasBlock(id2)
      chain.localTree.localTipId == gid

    # Ingesting child B2 again returns OrphanAlreadyBuffered
    let applyB2DupRes = chain.tryApplyBlock(b2)
    check:
      applyB2DupRes.isErr
      applyB2DupRes.error.kind == BlockApplyErrorKind.OrphanAlreadyBuffered

    # 2. Ingest parent B1
    let applyB1Res = chain.syncApplyBlock(b1)
    check:
      applyB1Res.isOk
      # 3. Both B1 and B2 should now be applied and promoted
      chain.localTree.hasBlock(id1)
      chain.localTree.hasBlock(id2)
      chain.localTree.localTipId == id2
      chain.ledger.state(id1).isSome
      chain.ledger.state(id2).isSome
      chain.orphanPool.len == 0

  test "multi-depth cascade: resolves B2, B3, B4 when B1 arrives":
    var (chain, genesis, gid) = setupChain()

    let
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, SlotNumber(2), [])
      id2 = blockId(b2.header)
      b3 = childBlock(b2.header, id2, SlotNumber(3), [])
      id3 = blockId(b3.header)
      b4 = childBlock(b3.header, id3, SlotNumber(4), [])
      id4 = blockId(b4.header)

    # Ingest B4, B3, B2 out of order
    check:
      chain.tryApplyBlock(b4).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.tryApplyBlock(b3).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.tryApplyBlock(b2).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.orphanPool.len == 3
      # Ingest B1
      chain.syncApplyBlock(b1).isOk
      # All 4 blocks must be applied in order
      chain.localTree.hasBlock(id1)
      chain.localTree.hasBlock(id2)
      chain.localTree.hasBlock(id3)
      chain.localTree.hasBlock(id4)
      chain.localTree.localTipId == id4
      chain.orphanPool.len == 0

  test "structurally invalid block or invalid header is rejected and not buffered":
    var
      (chain, genesis, gid) = setupChain()
      invalidHdrBlock = childBlock(genesis.header, gid, SlotNumber(1), [])
    invalidHdrBlock.header.bedrockVersion = 99'u8 # invalid version
    let applyHdrRes = chain.tryApplyBlock(invalidHdrBlock)
    check:
      applyHdrRes.isErr
      applyHdrRes.error.kind == BlockApplyErrorKind.InvalidStructure
      chain.orphanPool.len == 0

    var invalidStructBlock = childBlock(genesis.header, gid, SlotNumber(1), [])
    invalidStructBlock.signature = DefaultEd25519Signature # zero signature
    let applyStructRes = chain.tryApplyBlock(invalidStructBlock)
    check:
      applyStructRes.isErr
      applyStructRes.error.kind == BlockApplyErrorKind.InvalidStructure
      chain.orphanPool.len == 0

  test "chain respects MaxOrphans capacity limit and evicts oldest":
    var
      (chain, _, gid) = setupChain()
      blocks: seq[Block]
      parent = gid
    for i in 1 .. MaxOrphans + 2:
      let blk = childBlock(chain.genesisBlock.header, parent, SlotNumber(i), [])
      blocks.add(blk)
      parent = blockId(blk.header)

    # Ingest MaxOrphans orphans (from index 1 onward, parent missing because blocks[0] not added)
    for i in 1 .. MaxOrphans:
      check chain.tryApplyBlock(blocks[i]).error.kind == BlockApplyErrorKind.OrphanBuffered
    check:
      chain.orphanPool.len == MaxOrphans
      chain.orphanPool.hasOrphan(blockId(blocks[1].header))
      # Ingest blocks[MaxOrphans + 1] (evicts oldest blocks[1] and purges its descendant chain)
      chain.tryApplyBlock(blocks[MaxOrphans + 1]).error.kind == BlockApplyErrorKind.OrphanBuffered
      not chain.orphanPool.hasOrphan(blockId(blocks[1].header))
      not chain.orphanPool.hasOrphan(blockId(blocks[2].header))
      chain.orphanPool.hasOrphan(blockId(blocks[MaxOrphans + 1].header))
      chain.orphanPool.len == 1

  test "chain re-buffers evicted orphan and resolves cascade upon parent arrival":
    var
      (chain, _, gid) = setupChain()
      blocks: seq[Block]
      parent = gid
    for i in 1 .. MaxOrphans + 2:
      let blk = childBlock(chain.genesisBlock.header, parent, SlotNumber(i), [])
      blocks.add(blk)
      parent = blockId(blk.header)

    # Ingest blocks[1 .. MaxOrphans]
    for i in 1 .. MaxOrphans:
      check chain.tryApplyBlock(blocks[i]).error.kind == BlockApplyErrorKind.OrphanBuffered

    # Ingest blocks[MaxOrphans + 1] (evicts blocks[1] and purges descendant chain)
    check:
      chain.tryApplyBlock(blocks[MaxOrphans + 1]).error.kind == BlockApplyErrorKind.OrphanBuffered
      not chain.orphanPool.hasOrphan(blockId(blocks[1].header))

    # Re-ingest blocks[1 .. MaxOrphans - 1] in sequential order (fitting within capacity alongside MaxOrphans + 1)
    for i in 1 .. MaxOrphans - 1:
      check chain.tryApplyBlock(blocks[i]).error.kind == BlockApplyErrorKind.OrphanBuffered
    check:
      chain.orphanPool.hasOrphan(blockId(blocks[1].header))
      chain.orphanPool.hasOrphan(blockId(blocks[MaxOrphans + 1].header))
      chain.orphanPool.len == MaxOrphans
      # Ingest parent blocks[0] (child of genesis) -> cascade-promotes blocks[0 .. MaxOrphans - 1]
      chain.syncApplyBlock(blocks[0]).isOk
    for i in 0 .. MaxOrphans - 1:
      check chain.localTree.hasBlock(blockId(blocks[i].header))
    check:
      chain.localTree.localTipId == blockId(blocks[MaxOrphans - 1].header)
      chain.orphanPool.len == 1 # only blocks[MaxOrphans + 1] remains
      chain.orphanPool.hasOrphan(blockId(blocks[MaxOrphans + 1].header))

  test "sibling forks: promotes both competing child blocks when shared parent arrives":
    var (chain, genesis, gid) = setupChain()

    let
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
      # Competing sibling blocks both parented by B1 at different slots
      b2a = childBlock(b1.header, id1, SlotNumber(2), [])
      id2a = blockId(b2a.header)
      b2b = childBlock(b1.header, id1, SlotNumber(3), [])
      id2b = blockId(b2b.header)

    # Ingest both siblings as orphans
    check:
      chain.tryApplyBlock(b2a).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.tryApplyBlock(b2b).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.orphanPool.len == 2
      chain.orphanPool.hasOrphan(id2a)
      chain.orphanPool.hasOrphan(id2b)
      # Ingest parent B1 -> resolves both branches
      chain.syncApplyBlock(b1).isOk
      chain.localTree.hasBlock(id1)
      chain.localTree.hasBlock(id2a)
      chain.localTree.hasBlock(id2b)
      chain.orphanPool.len == 0

  test "branching tree cascade: resolves multi-branch orphan tree when root arrives":
    var (chain, genesis, gid) = setupChain()

    let
      # Tree structure:
      #            ┌── B2a (slot 2) ── B3a (slot 4)
      # B1 (slot 1)┤
      #            └── B2b (slot 3) ── B3b (slot 5)
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
      b2a = childBlock(b1.header, id1, SlotNumber(2), [])
      id2a = blockId(b2a.header)
      b3a = childBlock(b2a.header, id2a, SlotNumber(4), [])
      id3a = blockId(b3a.header)
      b2b = childBlock(b1.header, id1, SlotNumber(3), [])
      id2b = blockId(b2b.header)
      b3b = childBlock(b2b.header, id2b, SlotNumber(5), [])
      id3b = blockId(b3b.header)

    # Ingest entire orphan tree in reverse / mixed order
    check:
      chain.tryApplyBlock(b3b).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.tryApplyBlock(b3a).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.tryApplyBlock(b2b).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.tryApplyBlock(b2a).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.orphanPool.len == 4
      # Ingest root B1 -> all 4 orphan descendants across both branches are promoted
      chain.syncApplyBlock(b1).isOk
      chain.localTree.hasBlock(id1)
      chain.localTree.hasBlock(id2a)
      chain.localTree.hasBlock(id3a)
      chain.localTree.hasBlock(id2b)
      chain.localTree.hasBlock(id3b)
      chain.orphanPool.len == 0

  test "dangling sub-tree pruning: invalid promoted orphan purges all waiting descendants":
    var (chain, genesis, gid) = setupChain()

    let
      b1 = childBlock(genesis.header, gid, SlotNumber(2), [])
      id1 = blockId(b1.header)
      # b2 has slot 2 (equal to parent b1 slot 2): passes header and topology admission,
      # but fails PoL validation against parent state because slot is not > parent.slot
      b2 = childBlock(b1.header, id1, SlotNumber(2), [])
      id2 = blockId(b2.header)
      b3 = childBlock(b2.header, id2, SlotNumber(3), [])
      id3 = blockId(b3.header)
      b4 = childBlock(b3.header, id3, SlotNumber(4), [])
      id4 = blockId(b4.header)

    # Ingest b4, b3, b2 as orphans
    check:
      chain.tryApplyBlock(b4).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.tryApplyBlock(b3).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.tryApplyBlock(b2).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.orphanPool.len == 3
      # Ingest parent b1 -> triggers promotion of b2, which fails state validation.
      # Its descendants b3 and b4 must be pruned immediately.
      chain.syncApplyBlock(b1).isOk
      chain.localTree.hasBlock(id1)
      not chain.localTree.hasBlock(id2)
      not chain.localTree.hasBlock(id3)
      not chain.localTree.hasBlock(id4)
      # The pool must have no dangling dead descendants remaining
      chain.orphanPool.len == 0

  test "orphan branching off unfinalized fork below LIB is rejected immediately":
    var (chain, genesis, gid) = setupChain()

    let
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
      b2a = childBlock(b1.header, id1, SlotNumber(2), [])
      id2a = blockId(b2a.header)
      b2b = childBlock(b1.header, id1, SlotNumber(3), [])
      id2b = blockId(b2b.header)
      b3a = childBlock(b2a.header, id2a, SlotNumber(4), [])

    # Apply b1, b2a, b2b, b3a to tree
    check:
      chain.tryApplyBlock(b1).isOk
      chain.tryApplyBlock(b2a).isOk
      chain.tryApplyBlock(b2b).isOk
      chain.tryApplyBlock(b3a).isOk

    # Finalize branch A at height 2 (B_imm = b2a)
    chain.localTree.latestImmutableHeight = 2
    check chain.localTree.latestImmutableBlockId == id2a

    # Ingest orphan branching off b2b (which violates LIB b2a)
    let
      uncommittedParent = childBlock(b2b.header, id2b, SlotNumber(6), [])

    # First buffer uncommittedParent: parent b2b is in localTree, but not a descendant of b2a (LIB).
    # uncommittedParent fails canDescendFromImmutable and is rejected immediately.
    check:
      chain.tryApplyBlock(uncommittedParent).error.kind == BlockApplyErrorKind.UnviableFork
      chain.orphanPool.len == 0

  test "orphan with invalid stateless transaction is buffered on ingestion and rejected during promotion":
    var
      (chain, genesis, gid) = setupChain()
      badTx = signedTxWithOps(1, 1)
    badTx.opProofs = @[] # MismatchedOpProofCount

    let
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      b1Id = blockId(b1.header)
      orphan = childBlock(b1.header, b1Id, SlotNumber(2), [badTx])
      # Ingestion: orphan is buffered without expensive tx validation
      applyRes = chain.tryApplyBlock(orphan)
    check:
      applyRes.isErr
      applyRes.error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.orphanPool.len == 1

    # When parent arrives, promotion runs stateless transaction validation and rejects the invalid orphan
    let b1Res = chain.syncApplyBlock(b1)
    check:
      b1Res.isOk
      chain.localTree.localTipId == b1Id
      chain.orphanPool.len == 0
      not chain.localTree.hasBlock(blockId(orphan.header))

  test "orphan cascade triggering a reorg restores mempool transactions from abandoned branch":
    var (chain, genesis, gid) = setupChain(securityParam = 1)

    let txA = minimalSignedTx()
    check:
      chain.mempool.add(ValidSignedMantleTx(txA), SlotNumber(1)).get
      chain.mempool.len == 1

    # Branch A: block a1 with txA
    let
      a1 = childBlock(genesis.header, gid, SlotNumber(1), [txA])
      resA1 = chain.tryApplyBlock(a1)
    check:
      resA1.isOk
      chain.localTree.localTipId == blockId(a1.header)
      chain.mempool.len == 0 # Pruned on block commit

    # Branch B: blocks b1 -> b2 -> b3 (heavier/taller branch)
    let
      b1 = childBlock(genesis.header, gid, SlotNumber(2), [])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, SlotNumber(3), [])
      id2 = blockId(b2.header)
      b3 = childBlock(b2.header, id2, SlotNumber(4), [])
      id3 = blockId(b3.header)

    # Ingest b3 and b2 as orphans
    check:
      chain.tryApplyBlock(b3).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.tryApplyBlock(b2).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.orphanPool.len == 2
      # Ingest root b1 -> cascade promotes b2 and b3, triggering a reorg from a1 to b3
      chain.syncApplyBlock(b1).isOk
      chain.localTree.localTipId == id3
      chain.orphanPool.len == 0
      # txA from abandoned branch A is restored to mempool
      chain.mempool.len == 1
      # LIB advanced to b2 (height 3 - securityParam 1 = 2)
      chain.localTree.latestImmutableBlockId == id2

  test "orphan pool prunes orphans whose ancestry cannot descend from newly advanced LIB":
    var (chain, genesis, gid) = setupChain(securityParam = 1)

    # Unfinalized fork block f1
    let
      f1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      idF1 = blockId(f1.header)
    check chain.tryApplyBlock(f1).isOk

    # Orphan o2 extends unknown block o1 which extends f1
    let
      o1 = childBlock(f1.header, idF1, SlotNumber(2), [])
      idO1 = blockId(o1.header)
      o2 = childBlock(o1.header, idO1, SlotNumber(3), [])
    check:
      chain.tryApplyBlock(o2).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.orphanPool.len == 1

    # Canonical chain extends on competing branch A: a1 -> a2 -> a3 -> a4
    let
      a1 = childBlock(genesis.header, gid, SlotNumber(2), [])
      idA1 = blockId(a1.header)
      a2 = childBlock(a1.header, idA1, SlotNumber(4), [])
      idA2 = blockId(a2.header)
      a3 = childBlock(a2.header, idA2, SlotNumber(5), [])
      idA3 = blockId(a3.header)
      a4 = childBlock(a3.header, idA3, SlotNumber(6), [])

    check:
      chain.tryApplyBlock(a1).isOk
      chain.tryApplyBlock(a2).isOk
      chain.tryApplyBlock(a3).isOk
      # Applying a4 advances LIB to a3 (height 4 - 1 = 3), pruning fork f1 (height 1)
      chain.tryApplyBlock(a4).isOk
      chain.localTree.latestImmutableBlockId == idA3
      # Orphan o2 had slot 3 <= LIB slot 5, so pruneIncompatibleWithImmutable pruned it from orphanPool on LIB update!
      chain.orphanPool.len == 0

  test "asynchronous promotion: LIB advancement invalidating admitted child purges its orphan descendants":
    var (chain, genesis, gid) = setupChain(securityParam = 1)

    # Branch B root
    let
      b1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      idB1 = blockId(b1.header)
      # Branch B child b2 (slot 3) and grandchild b3 (slot 7)
      b2 = childBlock(b1.header, idB1, SlotNumber(3), [])
      idB2 = blockId(b2.header)
      b3 = childBlock(b2.header, idB2, SlotNumber(7), [])
      idB3 = blockId(b3.header)

    # 1. Ingest b3 as an orphan (waiting for b2)
    check:
      chain.tryApplyBlock(b3).error.kind == BlockApplyErrorKind.OrphanBuffered
      # 2. Ingest b2 as an orphan (waiting for b1)
      chain.tryApplyBlock(b2).error.kind == BlockApplyErrorKind.OrphanBuffered
      chain.orphanPool.len == 2
      # 3. Ingest b1: b1 applies, and b2 is extracted via takeChildren for promotion
      chain.tryApplyBlock(b1).isOk
    let promotedChildren = chain.orphanPool.takeChildren(idB1)
    check:
      promotedChildren.len == 1
      blockId(promotedChildren[0].header) == idB2
      # b3 is still in orphanPool waiting on b2
      chain.orphanPool.hasOrphan(idB3)
      chain.orphanPool.len == 1

    # 4. Before b2 runs tryApplyAdmittedBlock, competing Branch A advances and moves LIB:
    # a1 (slot 2) -> a2 (slot 4) -> a3 (slot 5) -> a4 (slot 6)
    let
      a1 = childBlock(genesis.header, gid, SlotNumber(2), [])
      idA1 = blockId(a1.header)
      a2 = childBlock(a1.header, idA1, SlotNumber(4), [])
      idA2 = blockId(a2.header)
      a3 = childBlock(a2.header, idA2, SlotNumber(5), [])
      idA3 = blockId(a3.header)
      a4 = childBlock(a3.header, idA3, SlotNumber(6), [])

    check:
      chain.tryApplyBlock(a1).isOk
      chain.tryApplyBlock(a2).isOk
      chain.tryApplyBlock(a3).isOk
      chain.tryApplyBlock(a4).isOk
      # LIB advanced to a3 (height 3, slot 5), pruning branch b1
      chain.localTree.latestImmutableBlockId == idA3
      # b3 (slot 7 > LIB slot 5) was not pruned by LIB slot check alone
      chain.orphanPool.hasOrphan(idB3)

    # 5. Asynchronous promotion executes tryApplyAdmittedBlock(b2):
    # b2 has slot 3 <= LIB slot 5 -> checkViability returns UnviableFork
    let res = chain.tryApplyAdmittedBlock(promotedChildren[0])
    check:
      res.isErr
      res.error.kind == BlockApplyErrorKind.UnviableFork
      # With the fix, tryApplyAdmittedBlock pruned descendants of b2 upon failure -> b3 is purged!
      not chain.orphanPool.hasOrphan(idB3)
      chain.orphanPool.len == 0

{.pop.}
