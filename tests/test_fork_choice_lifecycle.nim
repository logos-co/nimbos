# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  chronos/unittest2/asynctests,
  results,
  ./testutil,
  ./logos_chain/sync/helpers,
  ../logos_chain/fork_choice_lifecycle,
  ../logos_chain/chain/block_processor,
  ../logos_chain/consensus/[clock, consensus_state],
  ../logos_chain/node_state

suite "fork_choice_lifecycle":
  test "restart selects startup rule from saved state, grace period, and tree LIB":
    let
      genesisBlk = testGenesisBlock()
      gid = blockId(genesisBlk.header)
      b1 = childBlock(genesisBlk.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
      b2 = childBlock(b1.header, id1, SlotNumber(2), [])
      nowUnix = nowWallclockSeconds()
      graceSecs = uint64(OfflineGracePeriodDuration.seconds)

    proc makeLoadedProcessor(): BlockProcessor =
      var chain = initTestChain(genesisBlk, securityParam = 1'u64)
      doAssert chain.tryApplyBlock(b1).isOk
      doAssert chain.tryApplyBlock(b2).isOk
      BlockProcessor.new(chain)

    withTempDir(tmpDir, "test_lifecycle_restart"):
      # 1. Fresh dataDir (no saved state) -> Bootstrap
      let
        bpCold = BlockProcessor.new(initTestChain(genesisBlk))
        lcCold = ForkChoiceLifecycle.init(bpCold, tmpDir)
      check:
        not lcCold.canProposeBlocks
        bpCold.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap

      # 2. Within 20m grace + matching non-genesis LIB in tree -> Online, gated until onIbdComplete
      let bpGrace = makeLoadedProcessor()
      check:
        bpGrace.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap
        saveNodeState(tmpDir, nowUnix - 60, id1).isOk
      let lcGrace = ForkChoiceLifecycle.init(bpGrace, tmpDir)
      check:
        bpGrace.consensus.forkChoiceRule == ForkChoiceRule.Online
        bpGrace.consensus.latestImmutable.tip == id1
        not lcGrace.canProposeBlocks
      lcGrace.onIbdComplete()
      check lcGrace.canProposeBlocks

      # 3. Future timestamp (clock skew) -> Online
      let bpSkew = makeLoadedProcessor()
      check saveNodeState(tmpDir, nowUnix + 300, id1).isOk
      discard ForkChoiceLifecycle.init(bpSkew, tmpDir)
      check bpSkew.consensus.forkChoiceRule == ForkChoiceRule.Online

      # 4. Explicit --bootstrap overrides within-grace state -> Bootstrap
      let bpExplicit = makeLoadedProcessor()
      check saveNodeState(tmpDir, nowUnix, id1).isOk
      discard ForkChoiceLifecycle.init(bpExplicit, tmpDir, explicitBootstrap = true)
      check bpExplicit.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap

      # 5. Offline longer than 20m -> Bootstrap
      let bpStale = makeLoadedProcessor()
      check saveNodeState(tmpDir, nowUnix - graceSecs - 10, id1).isOk
      discard ForkChoiceLifecycle.init(bpStale, tmpDir)
      check bpStale.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap

      # 6. Saved LIB at genesis -> Bootstrap
      let bpGenLib = makeLoadedProcessor()
      check saveNodeState(tmpDir, nowUnix, gid).isOk
      discard ForkChoiceLifecycle.init(bpGenLib, tmpDir)
      check bpGenLib.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap

      # 7. Saved non-genesis LIB absent from in-memory genesis tree -> Bootstrap
      let bpReset = BlockProcessor.new(initTestChain(genesisBlk))
      check saveNodeState(tmpDir, nowUnix, id1).isOk
      discard ForkChoiceLifecycle.init(bpReset, tmpDir)
      check bpReset.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap

  asyncTest "onIbdComplete with non-zero duration transitions after timer expires":
    let
      genesisBlk = testGenesisBlock()
      chain = initTestChain(genesisBlk)
    withTempDir(tmpDir, "test_lifecycle_timer"):
      let
        bp = BlockProcessor.new(chain)
        lifecycle = ForkChoiceLifecycle.init(bp, tmpDir, prolongedBootstrapDuration = chronos.milliseconds(50))

      check:
        bp.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap
        not lifecycle.canProposeBlocks
      lifecycle.onIbdComplete()

      # Before duration expires, still in Bootstrap
      check:
        bp.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap
        not lifecycle.canProposeBlocks
        loadNodeState(tmpDir).isNone
        waitUntil(lifecycle.canProposeBlocks, timeout = chronos.seconds(1))

      let saved = loadNodeState(tmpDir).get
      check:
        bp.consensus.forkChoiceRule == ForkChoiceRule.Online
        saved.libBlockId == bp.consensus.latestImmutable.tip
      await lifecycle.stop()

  asyncTest "start and stop manages heartbeat and prolonged bootstrap timers safely in Bootstrap mode":
    let
      genesisBlk = testGenesisBlock()
      chain = initTestChain(genesisBlk)
    withTempDir(tmpDir, "test_lifecycle_stop"):
      let
        bp = BlockProcessor.new(chain)
        lifecycle = ForkChoiceLifecycle.init(bp, tmpDir)
      lifecycle.start()
      check not lifecycle.canProposeBlocks

      lifecycle.onIbdComplete()
      check not lifecycle.canProposeBlocks

      await lifecycle.stop()
      check:
        # Processor remains in Bootstrap because timer was cancelled before expiry
        bp.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap
        not lifecycle.canProposeBlocks
        # Persist in Bootstrap mode does not write state
        loadNodeState(tmpDir).isNone

{.pop.}
