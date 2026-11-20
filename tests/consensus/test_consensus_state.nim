# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  ../testutil,
  ../logos_chain/sync/helpers,
  ../../logos_chain/core/types,
  ../../logos_chain/chain/chain

suite "consensus/fork_choice (via Chain.tryApplyBlock)":
  setup:
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)

  test "Bootstrap: deep fork wins by density, including a fork that previously lost":
    const
      k = 1'u64
      sGen = 10'u64
    let
      # Branch A: slots [5, 6, 30] -> density 2 from genesis (0, 10], density 1 from a1 (5, 15]
      a1 = childBlock(genesis.header, gid, SlotNumber(5), [])
      idA1 = blockId(a1.header)
      a2 = childBlock(a1.header, idA1, SlotNumber(6), [])
      idA2 = blockId(a2.header)
      a3 = childBlock(a2.header, idA2, SlotNumber(30), [])
      idA3 = blockId(a3.header)
      # Branch H off genesis: slots [2, 3] -> density 2 in (0, 10] (ties and loses to incumbent A3, beats B3)
      h1 = childBlock(genesis.header, gid, SlotNumber(2), [])
      idH1 = blockId(h1.header)
      h2 = childBlock(h1.header, idH1, SlotNumber(3), [])
      idH2 = blockId(h2.header)
      # Branch B off a1 (slot 5, height 1): slots [11, 12] -> density 2 in (5, 15] (beats A3), density 1 in (0, 10]
      b2 = childBlock(a1.header, idA1, SlotNumber(11), [])
      idB2 = blockId(b2.header)
      b3 = childBlock(b2.header, idB2, SlotNumber(12), [])

    var chain = initTestChain(genesis, securityParam = k, densitySlotWindow = sGen)
    check:
      chain.tryApplyBlock(a1).isOk
      chain.tryApplyBlock(a2).isOk
      chain.tryApplyBlock(a3).isOk
      chain.consensus.canonicalTip.id == idA3
      # H2 ties A3 on density (2 == 2 in (0, 10]) -> incumbent A3 is preserved
      chain.tryApplyBlock(h1).isOk
      chain.tryApplyBlock(h2).isOk
      chain.consensus.canonicalTip.id == idA3
      # B2 ties A3 in (5, 15] (1 == 1); B3 beats A3 (2 > 1), then tip sweep re-evaluates dormant H2 against B3 (2 > 1 in (0, 10]) -> H2 wins
      chain.tryApplyBlock(b2).isOk
      chain.consensus.canonicalTip.id == idA3
      chain.tryApplyBlock(b3).isOk
      chain.consensus.canonicalTip.id == idH2

  test "Online: shallow fork switches tip, advances LIB, and rejects blocks at or below LIB":
    const k = 2'u64
    let
      b1 = childBlock(genesis.header, gid, SlotNumber(2), [])
      idB1 = blockId(b1.header)
      b2 = childBlock(b1.header, idB1, SlotNumber(4), [])
      idB2 = blockId(b2.header)
      # Competing shallow fork off genesis (divergence 2 <= k): F1..F3
      f1 = childBlock(genesis.header, gid, SlotNumber(3), [])
      idF1 = blockId(f1.header)
      f2 = childBlock(f1.header, idF1, SlotNumber(5), [])
      idF2 = blockId(f2.header)
      f3 = childBlock(f2.header, idF2, SlotNumber(6), [])
      idF3 = blockId(f3.header)
      # Invalid blocks relative to LIB = f1 (height 1, slot 3)
      belowLibParent = childBlock(genesis.header, gid, SlotNumber(7), [])
      atLibSlot = childBlock(f1.header, idF1, SlotNumber(3), [])

    var chain = initTestChain(genesis, securityParam = k)
    chain.switchToOnline()
    check:
      chain.tryApplyBlock(b1).isOk
      chain.tryApplyBlock(b2).isOk
      chain.consensus.canonicalTip.id == idB2
      chain.consensus.latestImmutable.id == gid
      # Equal-height fork f2 preserves incumbent b2; taller f3 reorganizes tip and advances LIB to f1
      chain.tryApplyBlock(f1).isOk
      chain.tryApplyBlock(f2).isOk
      chain.consensus.canonicalTip.id == idB2
      chain.tryApplyBlock(f3).isOk
      chain.consensus.canonicalTip.id == idF3
      chain.consensus.latestImmutable.id == idF1
      # Abandoned fork (b1, b2) is pruned from consensus, BlockStore, and ledger
      not chain.consensus.hasBlock(idB1)
      not chain.consensus.hasBlock(idB2)
      chain.blockStore.getBlock(idB1).isNone
      not chain.ledger.hasState(idB1)
      # Blocks branching below LIB or at <= LIB.slot are rejected as UnviableFork
      chain.tryApplyBlock(belowLibParent).error.kind == BlockApplyErrorKind.UnviableFork
      chain.tryApplyBlock(atLibSlot).error.kind == BlockApplyErrorKind.UnviableFork

  test "LIB moves only after switchToOnline and prunes taller dead forks":
    const
      k = 2'u64
      sGen = 10'u64
    let
      # Taller sparse fork S (height 5, slots 20..24 -> density 0 in (0, 10])
      s1 = childBlock(genesis.header, gid, SlotNumber(20), [])
      idS1 = blockId(s1.header)
      s2 = childBlock(s1.header, idS1, SlotNumber(21), [])
      idS2 = blockId(s2.header)
      s3 = childBlock(s2.header, idS2, SlotNumber(22), [])
      idS3 = blockId(s3.header)
      s4 = childBlock(s3.header, idS3, SlotNumber(23), [])
      idS4 = blockId(s4.header)
      s5 = childBlock(s4.header, idS4, SlotNumber(24), [])
      idS5 = blockId(s5.header)
      # Denser canonical branch C (height 4, slots 1..4 -> density 4 in (0, 10])
      c1 = childBlock(genesis.header, gid, SlotNumber(1), [])
      idC1 = blockId(c1.header)
      c2 = childBlock(c1.header, idC1, SlotNumber(2), [])
      idC2 = blockId(c2.header)
      c3 = childBlock(c2.header, idC2, SlotNumber(3), [])
      idC3 = blockId(c3.header)
      c4 = childBlock(c3.header, idC3, SlotNumber(4), [])
      idC4 = blockId(c4.header)

    var chain = initTestChain(genesis, securityParam = k, densitySlotWindow = sGen)
    check:
      chain.tryApplyBlock(s1).isOk
      chain.tryApplyBlock(s2).isOk
      chain.tryApplyBlock(s3).isOk
      chain.tryApplyBlock(s4).isOk
      chain.consensus.canonicalTip.id == idS4
      chain.tryApplyBlock(c1).isOk
      chain.tryApplyBlock(c2).isOk
      chain.tryApplyBlock(c3).isOk
      chain.tryApplyBlock(c4).isOk
      chain.consensus.canonicalTip.id == idC4
      # Zero-density challenger S5 (height 5 > C4 height 4) loses immediately; LIB stays at genesis
      chain.tryApplyBlock(s5).isOk
      chain.consensus.canonicalTip.id == idC4
      chain.consensus.latestImmutable.id == gid
      chain.consensus.hasBlock(idS5)
      chain.blockStore.getBlock(idS5).isSome

    chain.switchToOnline()
    check:
      # LIB advances to c2 (height 4 - 2 = 2); entire fork S1..S5 (including S5 above tip height) is pruned
      chain.consensus.latestImmutable.id == idC2
      not chain.consensus.hasBlock(idS1)
      not chain.consensus.hasBlock(idS5)
      chain.blockStore.getBlock(idS1).isNone
      chain.blockStore.getBlock(idS5).isNone
      not chain.ledger.hasState(idS5)
      # Canonical pre-LIB ledger states pruned, canonical BlockStore bodies retained for IBD
      not chain.ledger.hasState(gid)
      not chain.ledger.hasState(idC1)
      chain.ledger.hasState(idC2)
      chain.blockStore.getBlock(gid).isSome
      chain.blockStore.getBlock(idC1).isSome

    # Calling switchToOnline again is a no-op
    chain.switchToOnline()
    check chain.consensus.latestImmutable.id == idC2

{.pop.}
