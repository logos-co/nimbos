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
  ../../logos_chain/core/[types, local_tree, utils],
  ../../logos_chain/consensus/consensus_state,
  ../../logos_chain/chain/[genesis, chain, block_processor]

suite "consensus/consensus_state (densitySlotWindow)":
  test "computes s_gen = ⌊k / (4f)⌋ exactly":
    # Default parameters: k = 2160, f = 1/30 -> (2160 * 30) / 4 = 16200 slots (4h 30m)
    let fDefault = NonNegativeRatio(num: 1, den: 30)
    check densitySlotWindow(2160'u64, fDefault) == 16200'u64

    # Custom ratio: k = 10, f = 1/2 -> (10 * 2) / 4 = 5 slots
    let fHalf = NonNegativeRatio(num: 1, den: 2)
    check densitySlotWindow(10'u64, fHalf) == 5'u64

    # Custom ratio: k = 20, f = 1/4 -> (20 * 4) / 4 = 20 slots
    let fQuarter = NonNegativeRatio(num: 1, den: 4)
    check densitySlotWindow(20'u64, fQuarter) == 20'u64

  test "overflow and zero arithmetic guards":
    # Zero numerator, denominator, or security parameter
    check densitySlotWindow(2160'u64, NonNegativeRatio(num: 0, den: 30)) == 0'u64
    check densitySlotWindow(2160'u64, NonNegativeRatio(num: 1, den: 0)) == 0'u64
    check densitySlotWindow(0'u64, NonNegativeRatio(num: 1, den: 30)) == 0'u64

    # Extreme numbers: securityParam * den > uint64.high does not overflow/wrap and saturates
    let fHugeDen = NonNegativeRatio(num: 1, den: uint64.high)
    let windowLarge = densitySlotWindow(1000'u64, fHugeDen)
    check windowLarge == uint64.high

    # 128-bit product (k * den) evaluated without overflow into 64-bit quotient
    let fHalfMax = NonNegativeRatio(num: 2, den: uint64.high div 2'u64)
    check densitySlotWindow(2'u64, fHalfMax) == ((uint64.high div 2'u64) * 2'u64) div 8'u64

    # Extreme num: 4 * num > uint64.high
    let fHugeNum = NonNegativeRatio(num: uint64.high div 2'u64, den: 1)
    let windowSmall = densitySlotWindow(1000'u64, fHugeNum)
    check windowSmall == 0'u64

suite "consensus/consensus_state (countChainDensity)":
  test "counts only blocks within the half-open window (lcaSlot, lcaSlot + densitySlotWindow]":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      tree = LocalTree.init(genesis)

      # Genesis is at slot 0
      # LCA block at slot 10
      b1 = childBlock(genesis.header, gid, slot = 10'u64, [sm])
      id1 = blockId(b1.header)

      # Chain A: slots 15, 25, 45
      b2 = childBlock(b1.header, id1, slot = 15'u64, [sm])
      id2 = blockId(b2.header)
      b3 = childBlock(b2.header, id2, slot = 25'u64, [sm])
      id3 = blockId(b3.header)
      b4 = childBlock(b3.header, id3, slot = 45'u64, [sm])
      id4 = blockId(b4.header)

    check tree.addBlockToTree(b1)
    check tree.addBlockToTree(b2)
    check tree.addBlockToTree(b3)
    check tree.addBlockToTree(b4)

    # Window of 20 slots starting from LCA slot 10 -> interval (10, 30]
    # Blocks in window: slot 15, slot 25 -> count = 2
    # Block at slot 45 is outside (> 30) -> not counted
    # Block at slot 10 is LCA (<= 10) -> not counted
    check countChainDensity(tree, id4, lcaSlot = 10'u64, lcaHeight = 1'u64, densitySlotWindow = 20'u64) == 2'u64

    # Window of 5 slots from slot 10 -> interval (10, 15]
    # Blocks in window: slot 15 -> count = 1
    check countChainDensity(tree, id4, lcaSlot = 10'u64, lcaHeight = 1'u64, densitySlotWindow = 5'u64) == 1'u64

    # Window of 40 slots from slot 10 -> interval (10, 50]
    # Blocks in window: slot 15, 25, 45 -> count = 3
    check countChainDensity(tree, id4, lcaSlot = 10'u64, lcaHeight = 1'u64, densitySlotWindow = 40'u64) == 3'u64

suite "consensus/consensus_state (preferCandidate - Online Rule)":
  test "Online: shallow fork (<= k) selects strictly longer chain":
    const k = 5'u64
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      f = NonNegativeRatio(num: 1, den: 10)
      sGen = densitySlotWindow(k, f)
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

    check fc.localTree.addBlockToTree(b1)
    check fc.localTree.addBlockToTree(b2)
    check fc.localTree.addBlockToTree(f2)
    check fc.localTree.addBlockToTree(f3)

    # Current tip is id2 (height 2).
    # Candidate idF2 (height 2) is equal length -> should NOT prefer (tie preserves current)
    check not fc.preferCandidate(currentTipId = id2, candidateId = idF2)

    # Candidate idF3 (height 3) is strictly longer (and divergence depth = 2 - 1 = 1 <= k) -> PREFER!
    check fc.preferCandidate(currentTipId = id2, candidateId = idF3)

  test "Online: strictly rejects deep forks (> k divergence depth)":
    const k = 2'u64 # securityParam k = 2
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      f = NonNegativeRatio(num: 1, den: 10)
      sGen = densitySlotWindow(k, f)
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

    check fc.localTree.addBlockToTree(b1)
    check fc.localTree.addBlockToTree(b2)
    check fc.localTree.addBlockToTree(b3)
    check fc.localTree.addBlockToTree(b4)
    check fc.localTree.addBlockToTree(f1)
    check fc.localTree.addBlockToTree(f2)
    check fc.localTree.addBlockToTree(f3)
    check fc.localTree.addBlockToTree(f4)
    check fc.localTree.addBlockToTree(f5)

    # Even though candidate idF5 (height 5) is longer than id4 (height 4),
    # under Online rule, deep fork (> k = 2 divergence) is strictly rejected!
    check not fc.preferCandidate(currentTipId = id4, candidateId = idF5)

suite "consensus/consensus_state (preferCandidate - Bootstrap Rule)":
  test "Bootstrap: shallow fork (<= k) selects strictly longer chain":
    const k = 5'u64
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      f = NonNegativeRatio(num: 1, den: 10)
      sGen = densitySlotWindow(k, f)
      fc = ConsensusState.init(genesis, securityParam = k, densitySlotWindow = sGen, forkChoiceRule = ForkChoiceRule.Bootstrap)

      b1 = childBlock(genesis.header, gid, slot = 1'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, slot = 2'u64, [sm])
      id2 = blockId(b2.header)

      f2 = childBlock(b1.header, id1, slot = 3'u64, [sm])
      idF2 = blockId(f2.header)
      f3 = childBlock(f2.header, idF2, slot = 4'u64, [sm])
      idF3 = blockId(f3.header)

    check fc.localTree.addBlockToTree(b1)
    check fc.localTree.addBlockToTree(b2)
    check fc.localTree.addBlockToTree(f2)
    check fc.localTree.addBlockToTree(f3)

    # Shallow fork in Bootstrap mode: longest chain wins
    check fc.preferCandidate(currentTipId = id2, candidateId = idF3)
    check not fc.preferCandidate(currentTipId = id2, candidateId = idF2)

  test "Bootstrap: deep fork (> k) uses density check in s_gen window (dense candidate wins)":
    const k = 2'u64
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      # f = 1/20 -> s_gen = (2 * 20) / 4 = 10 slots
      f = NonNegativeRatio(num: 1, den: 20)
      sGen = densitySlotWindow(k, f)
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

    check fc.localTree.addBlockToTree(b1)
    check fc.localTree.addBlockToTree(b2)
    check fc.localTree.addBlockToTree(b3)
    check fc.localTree.addBlockToTree(b4)
    check fc.localTree.addBlockToTree(c1)
    check fc.localTree.addBlockToTree(c2)
    check fc.localTree.addBlockToTree(c3)

    # Local chain has length 4, candidate has length 3.
    # Divergence depth from genesis is 4 > k = 2.
    # In window (0, 10]:
    # Local chain density = 1 (b1 at slot 8)
    # Candidate chain density = 3 (c1, c2, c3 at slots 2, 4, 6)
    # Candidate is denser in s_gen window -> Candidate WINS despite shorter total height!
    check fc.preferCandidate(currentTipId = id4, candidateId = idC3)

  test "Bootstrap: deep fork preserves local chain if candidate is less dense":
    const k = 2'u64
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      f = NonNegativeRatio(num: 1, den: 20) # s_gen = 10 slots
      sGen = densitySlotWindow(k, f)
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

    check fc.localTree.addBlockToTree(b1)
    check fc.localTree.addBlockToTree(b2)
    check fc.localTree.addBlockToTree(b3)
    check fc.localTree.addBlockToTree(a1)
    check fc.localTree.addBlockToTree(a2)
    check fc.localTree.addBlockToTree(a3)
    check fc.localTree.addBlockToTree(a4)
    check fc.localTree.addBlockToTree(a5)

    # Local density = 3, Attacker density = 1.
    # Attacker fork is rejected under Bootstrap rule despite attacker having height 5 vs local height 3!
    check not fc.preferCandidate(currentTipId = id3, candidateId = idA5)

  test "Bootstrap: equal density on deep fork preserves local incumbent chain":
    const k = 2'u64
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      f = NonNegativeRatio(num: 1, den: 20) # s_gen = 10 slots
      sGen = densitySlotWindow(k, f)
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

    check fc.localTree.addBlockToTree(b1)
    check fc.localTree.addBlockToTree(b2)
    check fc.localTree.addBlockToTree(b3)
    check fc.localTree.addBlockToTree(b4)
    check fc.localTree.addBlockToTree(c1)
    check fc.localTree.addBlockToTree(c2)
    check fc.localTree.addBlockToTree(c3)
    check fc.localTree.addBlockToTree(c4)
    check fc.localTree.addBlockToTree(c5)

    # Both have density = 2 in window (0, 10].
    # Deep fork (> k=2) with equal density must NOT prefer candidate (tie breaks in favor of incumbent)
    check not fc.preferCandidate(currentTipId = id4, candidateId = idC5)

suite "consensus/consensus_state (density optimizations & cache)":
  test "highestAncestorInSlotWindow and height-delta countChainDensity":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      tree = LocalTree.init(genesis)

      # Genesis at slot 0 (height 0)
      # LCA at slot 10 (height 1)
      b1 = childBlock(genesis.header, gid, slot = 10'u64, [sm])
      id1 = blockId(b1.header)

      # Chain: slots 15 (height 2), 25 (height 3), 45 (height 4)
      b2 = childBlock(b1.header, id1, slot = 15'u64, [sm])
      id2 = blockId(b2.header)
      b3 = childBlock(b2.header, id2, slot = 25'u64, [sm])
      id3 = blockId(b3.header)
      b4 = childBlock(b3.header, id3, slot = 45'u64, [sm])
      id4 = blockId(b4.header)

    check tree.addBlockToTree(b1)
    check tree.addBlockToTree(b2)
    check tree.addBlockToTree(b3)
    check tree.addBlockToTree(b4)

    # Window (10, 30]: highest ancestor in window is b3 at slot 25 (height 3)
    check tree.highestAncestorInSlotWindow(id4, lcaSlot = 10'u64, maxSlot = 30'u64) == 3'u64

    # Height-delta density = height(b3) - height(b1) = 3 - 1 = 2
    check tree.countChainDensity(id4, lcaSlot = 10'u64, lcaHeight = 1'u64, densitySlotWindow = 20'u64) == 2'u64

    # When all blocks are above window (e.g. maxSlot = 12):
    check tree.highestAncestorInSlotWindow(id4, lcaSlot = 10'u64, maxSlot = 12'u64) == 0'u64
    check tree.countChainDensity(id4, lcaSlot = 10'u64, lcaHeight = 1'u64, densitySlotWindow = 2'u64) == 0'u64

  test "ForkChoiceDensityCache memoization, cache hits, and preferCandidate deep-fork integration":
    const k = 1'u64
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      f = NonNegativeRatio(num: 1, den: 20)
      sGen = densitySlotWindow(k, f) # (1 * 20) / 4 = 5 slots
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

    check fc.localTree.addBlockToTree(b1)
    check fc.localTree.addBlockToTree(b2)
    check fc.localTree.addBlockToTree(c1)
    check fc.localTree.addBlockToTree(c2)
    check fc.localTree.addBlockToTree(c3)

    check fc.cache.len == 0

    # 1. First lookup computes and populates cache for (id2, lcaSlot = 0)
    let d1 = fc.cache.getOrComputeDensity(fc.localTree, id2, lcaSlot = 0'u64, lcaHeight = 0'u64, densitySlotWindow = sGen)
    check d1 == 2'u64 # b1 (slot 2) and b2 (slot 4) in (0, 5]
    check fc.cache.len == 1

    # 2. Second lookup is an immediate cache hit
    let d2 = fc.cache.getOrComputeDensity(fc.localTree, id2, lcaSlot = 0'u64, lcaHeight = 0'u64, densitySlotWindow = sGen)
    check d2 == 2'u64
    check fc.cache.len == 1

    # 3. preferCandidate in deep fork mode (divergenceDepth = 2 > k = 1) exercises cache:
    # - idC3 density in (0, 5] = 2 (c1 at slot 3, c2 at slot 5; c3 at slot 7 is > 5)
    # - id2 density was already cached as 2
    # - Equal density -> tie preserves current tip id2 (returns false)
    # - Candidate idC3 is newly cached -> cache.len becomes 2
    check not fc.preferCandidate(currentTipId = id2, candidateId = idC3)
    check fc.cache.len == 2

    # 4. Repeated preferCandidate call is a full cache hit (cache.len stays 2)
    check not fc.preferCandidate(currentTipId = id2, candidateId = idC3)
    check fc.cache.len == 2

suite "consensus/consensus_state (rule initialization and transition)":
  test "Chain and BlockProcessor default to Bootstrap mode":
    let
      genesis = createGenesisBlock(testGenesisTx()).get
      chain = initTestChain(genesis, securityParam = 5'u64)
      bp = BlockProcessor.new(chain)

    check chain.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap
    check bp.forkChoiceRule == ForkChoiceRule.Bootstrap

  test "Runtime transition from Bootstrap to Online":
    let
      genesis = createGenesisBlock(testGenesisTx()).get
      chain = initTestChain(genesis, securityParam = 5'u64)
      bp = BlockProcessor.new(chain)

    check bp.forkChoiceRule == ForkChoiceRule.Bootstrap
    bp.switchToOnline()
    check chain.consensus.forkChoiceRule == ForkChoiceRule.Online
    check bp.forkChoiceRule == ForkChoiceRule.Online

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

    check chain.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap
    check chain.consensus.securityParam == 5'u64
    check chain.canonicalTip.tip == gid
    check chain.canonicalTip.slot == 0'u64
    check chain.canonicalTip.height == 0'u64

    # tryUpdateTip by candidate BlockId
    check chain.localTree.addBlockToTree(b1)
    chain.tryUpdateTip(id1)
    check chain.canonicalTip.tip == id1
    check chain.canonicalTip.slot == 1'u64
    check chain.canonicalTip.height == 1'u64

    # Re-evaluating current tip does not change tip
    chain.tryUpdateTip(id1)
    check chain.canonicalTip.tip == id1

    # tryUpdateTip by candidate BlockId
    check chain.localTree.addBlockToTree(b2)
    chain.tryUpdateTip(id2)
    check chain.canonicalTip.tip == id2
    check chain.canonicalTip.slot == 2'u64
    check chain.canonicalTip.height == 2'u64

  test "ConsensusState standalone initialization and tip tracking":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      b1 = childBlock(genesis.header, gid, slot = 1'u64, [sm])
      id1 = blockId(b1.header)
      cs = ConsensusState.init(genesis, securityParam = 5'u64, densitySlotWindow = 100'u64)

    check cs.canonicalTip.tip == gid
    check cs.canonicalTip.slot == 0'u64
    check cs.canonicalTip.height == 0'u64
    check cs.latestImmutableId == gid

    # Direct addition to cs.localTree and tip update without passing tree
    check cs.localTree.addBlockToTree(b1)
    cs.tryUpdateTip(id1)
    check cs.canonicalTip.tip == id1
    check cs.canonicalTip.slot == 1'u64
    check cs.canonicalTip.height == 1'u64

  test "ConsensusState tryUpdateLib updates latestImmutableId and prunes forks":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      cs = ConsensusState.init(genesis, securityParam = 1'u64, densitySlotWindow = 100'u64)
      b1 = childBlock(genesis.header, gid, slot = 1'u64, [sm])
      id1 = blockId(b1.header)
      f1 = childBlock(genesis.header, gid, slot = 2'u64, [sm])
      idF1 = blockId(f1.header)
      b2 = childBlock(b1.header, id1, slot = 3'u64, [sm])
      id2 = blockId(b2.header)

    check cs.latestImmutableHeight() == 0'u64
    check cs.latestImmutableSlot() == 0'u64

    check cs.localTree.addBlockToTree(b1)
    check cs.localTree.addBlockToTree(f1)
    cs.tryUpdateTip(id1)
    # tip is at height 1, secParam is 1 -> immHeight = 0, no change from genesis
    check cs.tryUpdateLib().len == 0
    check cs.latestImmutableId == gid

    check cs.localTree.addBlockToTree(b2)
    cs.tryUpdateTip(id2)
    # tip is at height 2, secParam is 1 -> immHeight = 1 (b1)
    let pruned = cs.tryUpdateLib()
    check idF1 in pruned
    check cs.latestImmutableId == id1
    check cs.latestImmutableHeight() == 1'u64
    check cs.latestImmutableSlot() == 1'u64
    check not cs.localTree.hasBlock(idF1)
    check cs.localTree.hasBlock(id1)

  test "ConsensusState canDescendFromImmutable validates ancestry and slot feasibility":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(testGenesisTx()).get
      gid = blockId(genesis.header)
      cs = ConsensusState.init(genesis, securityParam = 1'u64, densitySlotWindow = 100'u64)
      b1 = childBlock(genesis.header, gid, slot = 1'u64, [sm])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, slot = 3'u64, [sm])
      id2 = blockId(b2.header)

    check cs.localTree.addBlockToTree(b1)
    check cs.localTree.addBlockToTree(b2)
    cs.tryUpdateTip(id2)
    discard cs.tryUpdateLib()
    check cs.latestImmutableId == id1 # LIB is b1 (slot 1, height 1)

    # 1. Zero parent is rejected
    check not cs.canDescendFromImmutable(Header(parentBlock: default(BlockId), slot: 5))

    # 2. Block with slot <= LIB slot is rejected
    check not cs.canDescendFromImmutable(Header(parentBlock: id1, slot: 1))

    # 3. Known child of LIB with slot > LIB slot is accepted
    check cs.canDescendFromImmutable(Header(parentBlock: id1, slot: 4))

    # 4. Unknown parent (orphan) with slot > LIB slot is accepted
    var unknownParent: BlockId
    unknownParent[0] = 99'u8
    check cs.canDescendFromImmutable(Header(parentBlock: unknownParent, slot: 4))

    # 5. Unknown parent (orphan) with slot <= LIB slot is rejected
    check not cs.canDescendFromImmutable(Header(parentBlock: unknownParent, slot: 1))

{.pop.}
