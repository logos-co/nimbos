# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  ../testutil,
  ../logos_chain/sync/helpers,
  ../../logos_chain/core/[types, local_tree],
  ../../logos_chain/consensus/consensus_state,
  ../../logos_chain/chain/genesis

suite "consensus/consensus_state (preferCandidate - Online Rule)":
  test "Online: shallow fork (<= k) selects strictly longer chain":
    const
      k = 5'u64
      sGen = 12'u64 # f = 1/10: ⌊(k * f.den) / (4 * f.num)⌋ = ⌊(5 * 10) / 4⌋ = 12 slots
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      fc = ConsensusState.init(genesis, securityParam = k, densitySlotWindow = sGen, forkChoiceRule = ForkChoiceRule.Online)

      # Canonical branch: height 1 (b1), height 2 (b2)
      b1 = childBlock(genesis.header, gid, slot = 1'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, slot = 2'u64, [sm])
      id2 = blockId(b2.header)

      # Competing fork off b1: f2 (height 2), f3 (height 3)
      f2 = childBlock(b1.header, id1, slot = 3'u64, [sm])
      idF2 = blockId(f2.header)
      f3 = childBlock(f2.header, idF2, slot = 4'u64, [sm])
      idF3 = blockId(f3.header)

    check:
      fc.localTree.addBlockToTree(b1)
      fc.localTree.addBlockToTree(b2)
      fc.localTree.addBlockToTree(f2)
      fc.localTree.addBlockToTree(f3)

      # Current tip is id2 (height 2).
      # Candidate idF2 (height 2) is equal length -> should NOT prefer (tie preserves current)
      not fc.preferCandidate(currentTipId = id2, candidateId = idF2)

      # Candidate idF3 (height 3) is strictly longer (and divergence depth = 2 - 1 = 1 <= k) -> PREFER!
      fc.preferCandidate(currentTipId = id2, candidateId = idF3)

  test "Online: strictly rejects deep forks (> k divergence depth)":
    const
      k = 2'u64 # securityParam k = 2
      sGen = 5'u64 # f = 1/10: ⌊(k * f.den) / (4 * f.num)⌋ = ⌊(2 * 10) / 4⌋ = 5 slots
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      fc = ConsensusState.init(genesis, securityParam = k, densitySlotWindow = sGen, forkChoiceRule = ForkChoiceRule.Online)

      # Build canonical chain: genesis -> b1 -> b2 -> b3 -> b4 (height 4)
      b1 = childBlock(genesis.header, gid, slot = 1'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, slot = 2'u64, [sm])
      id2 = blockId(b2.header)
      b3 = childBlock(b2.header, id2, slot = 3'u64, [sm])
      id3 = blockId(b3.header)
      b4 = childBlock(b3.header, id3, slot = 4'u64, [sm])
      id4 = blockId(b4.header)

      # Build long alternative fork branching from genesis (height 0)
      # Divergence depth from current tip b4 is 4 - 0 = 4 > k (2)
      f1 = childBlock(genesis.header, gid, slot = 10'u64, [sm])
      idF1 = blockId(f1.header)
      f2 = childBlock(f1.header, idF1, slot = 11'u64, [sm])
      idF2 = blockId(f2.header)
      f3 = childBlock(f2.header, idF2, slot = 12'u64, [sm])
      idF3 = blockId(f3.header)
      f4 = childBlock(f3.header, idF3, slot = 13'u64, [sm])
      idF4 = blockId(f4.header)
      f5 = childBlock(f4.header, idF4, slot = 14'u64, [sm])
      idF5 = blockId(f5.header)

    check:
      fc.localTree.addBlockToTree(b1)
      fc.localTree.addBlockToTree(b2)
      fc.localTree.addBlockToTree(b3)
      fc.localTree.addBlockToTree(b4)
      fc.localTree.addBlockToTree(f1)
      fc.localTree.addBlockToTree(f2)
      fc.localTree.addBlockToTree(f3)
      fc.localTree.addBlockToTree(f4)
      fc.localTree.addBlockToTree(f5)

      # Even though candidate idF5 (height 5) is longer than id4 (height 4),
      # under Online rule, deep fork (> k = 2 divergence) is strictly rejected!
      not fc.preferCandidate(currentTipId = id4, candidateId = idF5)

suite "consensus/consensus_state (preferCandidate - Bootstrap Rule)":
  test "Bootstrap: shallow fork (<= k) selects strictly longer chain":
    const
      k = 5'u64
      sGen = 12'u64 # f = 1/10: ⌊(k * f.den) / (4 * f.num)⌋ = ⌊(5 * 10) / 4⌋ = 12 slots
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      fc = ConsensusState.init(genesis, securityParam = k, densitySlotWindow = sGen, forkChoiceRule = ForkChoiceRule.Bootstrap)

      b1 = childBlock(genesis.header, gid, slot = 1'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, slot = 2'u64, [sm])
      id2 = blockId(b2.header)

      f2 = childBlock(b1.header, id1, slot = 3'u64, [sm])
      idF2 = blockId(f2.header)
      f3 = childBlock(f2.header, idF2, slot = 4'u64, [sm])
      idF3 = blockId(f3.header)

    check:
      fc.localTree.addBlockToTree(b1)
      fc.localTree.addBlockToTree(b2)
      fc.localTree.addBlockToTree(f2)
      fc.localTree.addBlockToTree(f3)

      # Shallow fork in Bootstrap mode: longest chain wins
      fc.preferCandidate(currentTipId = id2, candidateId = idF3)
      not fc.preferCandidate(currentTipId = id2, candidateId = idF2)

  test "Bootstrap: deep fork (> k) uses density check in s_gen window (dense candidate wins)":
    const
      k = 2'u64
      sGen = 10'u64 # f = 1/20: ⌊(k * f.den) / (4 * f.num)⌋ = ⌊(2 * 20) / 4⌋ = 10 slots
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      fc = ConsensusState.init(genesis, securityParam = k, densitySlotWindow = sGen, forkChoiceRule = ForkChoiceRule.Bootstrap)

      # Local chain: sparse branch after genesis (LCA slot 0)
      # Produces 1 block in (0, 10] (at slot 8), then extends slowly to height 4 (slot 50, 60, 70)
      b1 = childBlock(genesis.header, gid, slot = 8'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, slot = 50'u64, [sm])
      id2 = blockId(b2.header)
      b3 = childBlock(b2.header, id2, slot = 60'u64, [sm])
      id3 = blockId(b3.header)
      b4 = childBlock(b3.header, id3, slot = 70'u64, [sm])
      id4 = blockId(b4.header)

      # Candidate chain (honest dense chain): produces 3 blocks in (0, 10] (slots 2, 4, 6)
      c1 = childBlock(genesis.header, gid, slot = 2'u64, [sm])
      idC1 = blockId(c1.header)
      c2 = childBlock(c1.header, idC1, slot = 4'u64, [sm])
      idC2 = blockId(c2.header)
      c3 = childBlock(c2.header, idC2, slot = 6'u64, [sm])
      idC3 = blockId(c3.header)

    check:
      fc.localTree.addBlockToTree(b1)
      fc.localTree.addBlockToTree(b2)
      fc.localTree.addBlockToTree(b3)
      fc.localTree.addBlockToTree(b4)
      fc.localTree.addBlockToTree(c1)
      fc.localTree.addBlockToTree(c2)
      fc.localTree.addBlockToTree(c3)

      # Local chain has length 4, candidate has length 3.
      # Divergence depth from genesis is 4 > k = 2.
      # In window (0, 10]:
      # Local chain density = 1 (b1 at slot 8)
      # Candidate chain density = 3 (c1, c2, c3 at slots 2, 4, 6)
      # Candidate is denser in s_gen window -> Candidate WINS despite shorter total height!
      fc.preferCandidate(currentTipId = id4, candidateId = idC3)

  test "Bootstrap: deep fork preserves local chain if candidate is less dense":
    const
      k = 2'u64
      sGen = 10'u64 # f = 1/20: ⌊(k * f.den) / (4 * f.num)⌋ = ⌊(2 * 20) / 4⌋ = 10 slots
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      fc = ConsensusState.init(genesis, securityParam = k, densitySlotWindow = sGen, forkChoiceRule = ForkChoiceRule.Bootstrap)

      # Local chain (dense in s_gen window): slots 2, 4, 6 -> density 3
      b1 = childBlock(genesis.header, gid, slot = 2'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, slot = 4'u64, [sm])
      id2 = blockId(b2.header)
      b3 = childBlock(b2.header, id2, slot = 6'u64, [sm])
      id3 = blockId(b3.header)

      # Candidate attacker chain (sparse in s_gen window, long afterwards):
      # slot 8 in window (density 1), then slots 100, 101, 102, 103 (total height 5)
      a1 = childBlock(genesis.header, gid, slot = 8'u64, [sm])
      idA1 = blockId(a1.header)
      a2 = childBlock(a1.header, idA1, slot = 100'u64, [sm])
      idA2 = blockId(a2.header)
      a3 = childBlock(a2.header, idA2, slot = 101'u64, [sm])
      idA3 = blockId(a3.header)
      a4 = childBlock(a3.header, idA3, slot = 102'u64, [sm])
      idA4 = blockId(a4.header)
      a5 = childBlock(a4.header, idA4, slot = 103'u64, [sm])
      idA5 = blockId(a5.header)

    check:
      fc.localTree.addBlockToTree(b1)
      fc.localTree.addBlockToTree(b2)
      fc.localTree.addBlockToTree(b3)
      fc.localTree.addBlockToTree(a1)
      fc.localTree.addBlockToTree(a2)
      fc.localTree.addBlockToTree(a3)
      fc.localTree.addBlockToTree(a4)
      fc.localTree.addBlockToTree(a5)

      # Local density = 3, Attacker density = 1.
      # Attacker fork is rejected under Bootstrap rule despite attacker having height 5 vs local height 3!
      not fc.preferCandidate(currentTipId = id3, candidateId = idA5)

  test "Bootstrap: equal density on deep fork preserves local incumbent chain":
    const
      k = 2'u64
      sGen = 10'u64 # f = 1/20: ⌊(k * f.den) / (4 * f.num)⌋ = ⌊(2 * 20) / 4⌋ = 10 slots
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      fc = ConsensusState.init(genesis, securityParam = k, densitySlotWindow = sGen, forkChoiceRule = ForkChoiceRule.Bootstrap)

      # Branch 1: slots 2, 4 (density = 2), slot 50, slot 60 (height 4)
      b1 = childBlock(genesis.header, gid, slot = 2'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, slot = 4'u64, [sm])
      id2 = blockId(b2.header)
      b3 = childBlock(b2.header, id2, slot = 50'u64, [sm])
      id3 = blockId(b3.header)
      b4 = childBlock(b3.header, id3, slot = 60'u64, [sm])
      id4 = blockId(b4.header)

      # Branch 2: slots 3, 5 (density = 2), slot 55, slot 65, slot 75 (height 5)
      c1 = childBlock(genesis.header, gid, slot = 3'u64, [sm])
      idC1 = blockId(c1.header)
      c2 = childBlock(c1.header, idC1, slot = 5'u64, [sm])
      idC2 = blockId(c2.header)
      c3 = childBlock(c2.header, idC2, slot = 55'u64, [sm])
      idC3 = blockId(c3.header)
      c4 = childBlock(c3.header, idC3, slot = 65'u64, [sm])
      idC4 = blockId(c4.header)
      c5 = childBlock(c4.header, idC4, slot = 75'u64, [sm])
      idC5 = blockId(c5.header)

    check:
      fc.localTree.addBlockToTree(b1)
      fc.localTree.addBlockToTree(b2)
      fc.localTree.addBlockToTree(b3)
      fc.localTree.addBlockToTree(b4)
      fc.localTree.addBlockToTree(c1)
      fc.localTree.addBlockToTree(c2)
      fc.localTree.addBlockToTree(c3)
      fc.localTree.addBlockToTree(c4)
      fc.localTree.addBlockToTree(c5)

      # Both have density = 2 in window (0, 10].
      # Deep fork (> k=2) with equal density must NOT prefer candidate (tie breaks in favor of incumbent)
      not fc.preferCandidate(currentTipId = id4, candidateId = idC5)

suite "consensus/consensus_state (ForkChoiceDensityCache)":
  test "ForkChoiceDensityCache memoization, cache hits, and preferCandidate deep-fork integration":
    const
      k = 1'u64
      sGen = 5'u64 # f = 1/20: ⌊(k * f.den) / (4 * f.num)⌋ = ⌊(1 * 20) / 4⌋ = 5 slots
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      fc = ConsensusState.init(genesis, securityParam = k, densitySlotWindow = sGen, forkChoiceRule = ForkChoiceRule.Bootstrap)

      # Branch B from genesis: b1 (slot 2, height 1), b2 (slot 4, height 2)
      b1 = childBlock(genesis.header, gid, slot = 2'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, slot = 4'u64, [sm])
      id2 = blockId(b2.header)

      # Competing branch C from genesis: c1 (slot 3), c2 (slot 5), c3 (slot 7, height 3)
      c1 = childBlock(genesis.header, gid, slot = 3'u64, [sm])
      idC1 = blockId(c1.header)
      c2 = childBlock(c1.header, idC1, slot = 5'u64, [sm])
      idC2 = blockId(c2.header)
      c3 = childBlock(c2.header, idC2, slot = 7'u64, [sm])
      idC3 = blockId(c3.header)

    check:
      fc.localTree.addBlockToTree(b1)
      fc.localTree.addBlockToTree(b2)
      fc.localTree.addBlockToTree(c1)
      fc.localTree.addBlockToTree(c2)
      fc.localTree.addBlockToTree(c3)
      # idC3 density in (0, 5] = 2 (c1 at slot 3, c2 at slot 5; c3 at slot 7 is > 5)
      # id2 density in (0, 5] = 2 (b1 at slot 2, b2 at slot 4)
      # Equal density tie -> preserves current tip id2 (returns false)
      not fc.preferCandidate(currentTipId = id2, candidateId = idC3)
      # Repeated call uses cached density and returns identical result
      not fc.preferCandidate(currentTipId = id2, candidateId = idC3)

suite "consensus/consensus_state (rule initialization and transition)":
  test "ConsensusState switchToOnline transitions rule":
    let
      genesis = createGenesisBlock(testGenesisTx()).get
      cs = ConsensusState.init(genesis, securityParam = 5'u64, densitySlotWindow = 100'u64, forkChoiceRule = ForkChoiceRule.Bootstrap)

    check cs.forkChoiceRule == ForkChoiceRule.Bootstrap
    cs.switchToOnline()
    check cs.forkChoiceRule == ForkChoiceRule.Online

  test "Chain initializes ConsensusState and performs tryUpdateTip":
    let
      sm = SignedMantleTx(testGenesisTx())
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      b1 = childBlock(genesis.header, gid, slot = 1'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, slot = 2'u64, [sm])
      id2 = blockId(b2.header)
      chain = initTestChain(genesis, securityParam = 5'u64)

    check:
      chain.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap
      chain.consensus.securityParam == 5'u64
      chain.consensus.canonicalTip.tip == gid
      chain.consensus.canonicalTip.slot == 0'u64
      chain.consensus.canonicalTip.height == 0'u64

    # tryUpdateTip by candidate BlockId
    check chain.consensus.localTree.addBlockToTree(b1)
    chain.consensus.tryUpdateTip(id1)
    check:
      chain.consensus.canonicalTip.tip == id1
      chain.consensus.canonicalTip.slot == 1'u64
      chain.consensus.canonicalTip.height == 1'u64

    # Re-evaluating current tip does not change tip
    chain.consensus.tryUpdateTip(id1)
    check chain.consensus.canonicalTip.tip == id1

    # tryUpdateTip by candidate BlockId
    check chain.consensus.localTree.addBlockToTree(b2)
    chain.consensus.tryUpdateTip(id2)
    check:
      chain.consensus.canonicalTip.tip == id2
      chain.consensus.canonicalTip.slot == 2'u64
      chain.consensus.canonicalTip.height == 2'u64

  test "ConsensusState standalone initialization and tip tracking":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      b1 = childBlock(genesis.header, gid, slot = 1'u64, [sm])
      id1 = blockId(b1.header)
      cs = ConsensusState.init(genesis, securityParam = 5'u64, densitySlotWindow = 100'u64, forkChoiceRule = ForkChoiceRule.Bootstrap)

    check:
      cs.canonicalTip.tip == gid
      cs.canonicalTip.slot == 0'u64
      cs.canonicalTip.height == 0'u64
      cs.latestImmutableId == gid

    # Direct addition to cs.localTree and tip update without passing tree
    check cs.localTree.addBlockToTree(b1)
    cs.tryUpdateTip(id1)
    check:
      cs.canonicalTip.tip == id1
      cs.canonicalTip.slot == 1'u64
      cs.canonicalTip.height == 1'u64

  test "ConsensusState tryUpdateLib updates latestImmutableId and prunes forks":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      cs = ConsensusState.init(genesis, securityParam = 1'u64, densitySlotWindow = 100'u64, forkChoiceRule = ForkChoiceRule.Bootstrap)
      b1 = childBlock(genesis.header, gid, slot = 1'u64, [sm])
      id1 = blockId(b1.header)
      f1 = childBlock(genesis.header, gid, slot = 2'u64, [sm])
      idF1 = blockId(f1.header)
      b2 = childBlock(b1.header, id1, slot = 3'u64, [sm])
      id2 = blockId(b2.header)

    check:
      cs.latestImmutableHeight() == 0'u64
      cs.latestImmutableSlot() == 0'u64
      cs.localTree.addBlockToTree(b1)
      cs.localTree.addBlockToTree(f1)
    cs.tryUpdateTip(id1)
    # tip is at height 1, secParam is 1 -> immHeight = 0, no change from genesis
    check:
      cs.tryUpdateLib().len == 0
      cs.latestImmutableId == gid
      cs.localTree.addBlockToTree(b2)
    cs.tryUpdateTip(id2)
    # tip is at height 2, secParam is 1 -> immHeight = 1 (b1)
    let pruned = cs.tryUpdateLib()
    check:
      idF1 in pruned
      cs.latestImmutableId == id1
      cs.latestImmutableHeight() == 1'u64
      cs.latestImmutableSlot() == 1'u64
      not cs.localTree.hasBlock(idF1)
      cs.localTree.hasBlock(id1)

  test "ConsensusState canDescendFromImmutable validates ancestry and slot feasibility":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      cs = ConsensusState.init(genesis, securityParam = 1'u64, densitySlotWindow = 100'u64, forkChoiceRule = ForkChoiceRule.Bootstrap)
      b1 = childBlock(genesis.header, gid, slot = 1'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, slot = 3'u64, [sm])
      id2 = blockId(b2.header)
      other1 = childBlock(genesis.header, gid, slot = 2'u64, [sm])
      idOther1 = blockId(other1.header)

    check:
      cs.localTree.addBlockToTree(b1)
      cs.localTree.addBlockToTree(b2)
    cs.tryUpdateTip(id2)
    discard cs.tryUpdateLib()

    var unknownParent: BlockId
    unknownParent[0] = 99'u8

    check:
      cs.latestImmutableId == id1 # LIB is b1 (slot 1, height 1)

      # 1. Zero parent is rejected
      not cs.canDescendFromImmutable(Header(parentBlock: default(BlockId), slot: 5))

      # 2. Block with slot <= LIB slot is rejected
      not cs.canDescendFromImmutable(Header(parentBlock: id1, slot: 1))

      # 3. Known child of LIB with slot > LIB slot is accepted
      cs.canDescendFromImmutable(Header(parentBlock: id1, slot: 4))

      # 4. Unknown parent (orphan) with slot > LIB slot is accepted
      cs.canDescendFromImmutable(Header(parentBlock: unknownParent, slot: 4))

      # 5. Unknown parent (orphan) with slot <= LIB slot is rejected
      not cs.canDescendFromImmutable(Header(parentBlock: unknownParent, slot: 1))

      # 6. Child of canonical tip (id2) is accepted
      cs.canDescendFromImmutable(Header(parentBlock: id2, slot: 5))

      # 7. Parent in tree at height <= LIB height is rejected (e.g. genesis parent)
      not cs.canDescendFromImmutable(Header(parentBlock: gid, slot: 4))

      # 8. Parent in tree with height >= LIB height that does not descend from LIB is rejected
      cs.localTree.addBlockToTree(other1)
      not cs.canDescendFromImmutable(Header(parentBlock: idOther1, slot: 5))

  test "Bootstrap: multi-fork candidate evaluation is robust across different block arrival orders":
    const
      k = 2'u64
      sGen = 10'u64 # f = 1/20: ⌊(k * f.den) / (4 * f.num)⌋ = ⌊(2 * 20) / 4⌋ = 10 slots
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)

      # Branch A (Incumbent): sparse in window (slot 8 -> density 1), height 4
      a1 = childBlock(genesis.header, gid, slot = 8'u64, [sm])
      idA1 = blockId(a1.header)
      a2 = childBlock(a1.header, idA1, slot = 50'u64, [sm])
      idA2 = blockId(a2.header)
      a3 = childBlock(a2.header, idA2, slot = 60'u64, [sm])
      idA3 = blockId(a3.header)
      a4 = childBlock(a3.header, idA3, slot = 70'u64, [sm])
      idA4 = blockId(a4.header)

      # Branch B (Moderate): 2 blocks in window (slots 3, 5 -> density 2), height 3
      b1 = childBlock(genesis.header, gid, slot = 3'u64, [sm])
      idB1 = blockId(b1.header)
      b2 = childBlock(b1.header, idB1, slot = 5'u64, [sm])
      idB2 = blockId(b2.header)
      b3 = childBlock(b2.header, idB2, slot = 55'u64, [sm])
      idB3 = blockId(b3.header)

      # Branch C (Dense): 3 blocks in window (slots 2, 4, 6 -> density 3), height 3
      c1 = childBlock(genesis.header, gid, slot = 2'u64, [sm])
      idC1 = blockId(c1.header)
      c2 = childBlock(c1.header, idC1, slot = 4'u64, [sm])
      idC2 = blockId(c2.header)
      c3 = childBlock(c2.header, idC2, slot = 6'u64, [sm])
      idC3 = blockId(c3.header)

    # Sequence 1: Incumbent A, then candidate B arrives, then candidate C arrives
    let fc1 = ConsensusState.init(genesis, securityParam = k, densitySlotWindow = sGen, forkChoiceRule = ForkChoiceRule.Bootstrap)
    check:
      fc1.localTree.addBlockToTree(a1)
      fc1.localTree.addBlockToTree(a2)
      fc1.localTree.addBlockToTree(a3)
      fc1.localTree.addBlockToTree(a4)
    fc1.tryUpdateTip(idA4)
    check fc1.canonicalTip.tip == idA4

    # B arrives: B density 2 > A density 1 -> B wins
    check:
      fc1.localTree.addBlockToTree(b1)
      fc1.localTree.addBlockToTree(b2)
      fc1.localTree.addBlockToTree(b3)
    fc1.tryUpdateTip(idB3)
    check fc1.canonicalTip.tip == idB3

    # C arrives: C density 3 > B density 2 -> C wins
    check:
      fc1.localTree.addBlockToTree(c1)
      fc1.localTree.addBlockToTree(c2)
      fc1.localTree.addBlockToTree(c3)
    fc1.tryUpdateTip(idC3)
    check fc1.canonicalTip.tip == idC3

    # Sequence 2: Incumbent A, then candidate C arrives first, then candidate B arrives second
    let fc2 = ConsensusState.init(genesis, securityParam = k, densitySlotWindow = sGen, forkChoiceRule = ForkChoiceRule.Bootstrap)
    check:
      fc2.localTree.addBlockToTree(a1)
      fc2.localTree.addBlockToTree(a2)
      fc2.localTree.addBlockToTree(a3)
      fc2.localTree.addBlockToTree(a4)
    fc2.tryUpdateTip(idA4)
    check fc2.canonicalTip.tip == idA4

    # C arrives first: C density 3 > A density 1 -> C wins
    check:
      fc2.localTree.addBlockToTree(c1)
      fc2.localTree.addBlockToTree(c2)
      fc2.localTree.addBlockToTree(c3)
    fc2.tryUpdateTip(idC3)
    check fc2.canonicalTip.tip == idC3

    # B arrives second: B density 2 < C density 3 -> C remains tip!
    check:
      fc2.localTree.addBlockToTree(b1)
      fc2.localTree.addBlockToTree(b2)
      fc2.localTree.addBlockToTree(b3)
    fc2.tryUpdateTip(idB3)
    check fc2.canonicalTip.tip == idC3

{.pop.}
