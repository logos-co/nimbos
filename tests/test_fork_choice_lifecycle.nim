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
  unittest2,
  results,
  ./testutil,
  ./logos_chain/sync/helpers,
  ../logos_chain/fork_choice_lifecycle,
  ../logos_chain/chain/block_processor,
  ../logos_chain/consensus/consensus_state,
  ../logos_chain/node_state

suite "fork_choice_lifecycle":
  test "determineStartupForkChoiceRule logic":
    const t0 = 1_000_000'u64

    check:
      # 1. Explicit --bootstrap flag -> Bootstrap
      determineStartupForkChoiceRule(
        explicitBootstrapFlag = true,
        isLibAtGenesis = false,
        lastOnlineTimestampUnix = Opt.some(t0),
        currentTimestampUnix = t0 + 100,
      ) == (ForkChoiceRule.Bootstrap, StartupForkChoiceReason.ExplicitFlag)

      # 2. LIB at Genesis -> Bootstrap
      determineStartupForkChoiceRule(
        explicitBootstrapFlag = false,
        isLibAtGenesis = true,
        lastOnlineTimestampUnix = Opt.some(t0),
        currentTimestampUnix = t0 + 100,
      ) == (ForkChoiceRule.Bootstrap, StartupForkChoiceReason.LibAtGenesis)

      # 3. Missing last online timestamp -> Bootstrap
      determineStartupForkChoiceRule(
        explicitBootstrapFlag = false,
        isLibAtGenesis = false,
        lastOnlineTimestampUnix = Opt.none(uint64),
        currentTimestampUnix = t0 + 100,
      ) == (ForkChoiceRule.Bootstrap, StartupForkChoiceReason.NoSavedState)

      # 4. Restart within 20m grace period -> Online
      determineStartupForkChoiceRule(
        explicitBootstrapFlag = false,
        isLibAtGenesis = false,
        lastOnlineTimestampUnix = Opt.some(t0),
        currentTimestampUnix = t0 + uint64(10.minutes.seconds),
      ) == (ForkChoiceRule.Online, StartupForkChoiceReason.WithinGrace)

      # 5. Exactly at grace period boundary (20m) -> Online
      determineStartupForkChoiceRule(
        explicitBootstrapFlag = false,
        isLibAtGenesis = false,
        lastOnlineTimestampUnix = Opt.some(t0),
        currentTimestampUnix = t0 + uint64(OfflineGracePeriodDuration.seconds),
      ) == (ForkChoiceRule.Online, StartupForkChoiceReason.WithinGrace)

      # 6. Exceeding grace period (>20m) -> Bootstrap
      determineStartupForkChoiceRule(
        explicitBootstrapFlag = false,
        isLibAtGenesis = false,
        lastOnlineTimestampUnix = Opt.some(t0),
        currentTimestampUnix = t0 + uint64(OfflineGracePeriodDuration.seconds) + 1,
      ) == (ForkChoiceRule.Bootstrap, StartupForkChoiceReason.OfflineTooLong)

      # 7. Instantaneous restart -> Online (within grace)
      determineStartupForkChoiceRule(
        explicitBootstrapFlag = false,
        isLibAtGenesis = false,
        lastOnlineTimestampUnix = Opt.some(t0),
        currentTimestampUnix = t0,
      ) == (ForkChoiceRule.Online, StartupForkChoiceReason.WithinGrace)

      # 8. Backwards clock skew does NOT prove node was offline > T_offline -> Online (per spec)
      determineStartupForkChoiceRule(
        explicitBootstrapFlag = false,
        isLibAtGenesis = false,
        lastOnlineTimestampUnix = Opt.some(t0),
        currentTimestampUnix = t0 - 100,
      ) == (ForkChoiceRule.Online, StartupForkChoiceReason.ClockSkew)

  asyncTest "onSyncComplete with ZeroDuration switches immediately to Online and persists":
    let
      genesisBlk = testGenesisBlock()
      chain = initTestChain(genesisBlk, forkChoiceRule = ForkChoiceRule.Bootstrap)
    withTempDir(tmpDir, "test_lifecycle_zero"):
      let
        bp = BlockProcessor.new(chain)
        lifecycle = ForkChoiceLifecycle.new(bp, tmpDir, prolongedBootstrapDuration = chronos.ZeroDuration)
      check:
        bp.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap
        not lifecycle.canProposeBlocks
      lifecycle.onSyncComplete()

      let saved = loadNodeState(tmpDir).get
      check:
        bp.consensus.forkChoiceRule == ForkChoiceRule.Online
        lifecycle.canProposeBlocks
        saved.libBlockId == bp.consensus.latestImmutableId

  asyncTest "onSyncComplete with non-zero duration transitions after timer expires":
    let
      genesisBlk = testGenesisBlock()
      chain = initTestChain(genesisBlk, forkChoiceRule = ForkChoiceRule.Bootstrap)
    withTempDir(tmpDir, "test_lifecycle_timer"):
      let
        bp = BlockProcessor.new(chain)
        lifecycle = ForkChoiceLifecycle.new(bp, tmpDir, prolongedBootstrapDuration = chronos.milliseconds(50))

      check:
        bp.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap
        not lifecycle.canProposeBlocks
      lifecycle.onSyncComplete()

      # Before duration expires, still in Bootstrap
      check:
        bp.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap
        not lifecycle.canProposeBlocks

      check waitUntil(lifecycle.canProposeBlocks, timeout = chronos.seconds(1))
      let saved = loadNodeState(tmpDir).get
      check:
        bp.consensus.forkChoiceRule == ForkChoiceRule.Online
        saved.libBlockId == bp.consensus.latestImmutableId

  asyncTest "persist writes node state only in Online mode":
    let genesisBlk = testGenesisBlock()
    withTempDir(tmpDir, "test_lifecycle_persist"):
      block:
        let
          chainBoot = initTestChain(genesisBlk, forkChoiceRule = ForkChoiceRule.Bootstrap)
          bp = BlockProcessor.new(chainBoot)
          lifecycle = ForkChoiceLifecycle.new(bp, tmpDir)
        check not lifecycle.canProposeBlocks
        await lifecycle.stop()
        # In Bootstrap mode, persist on stop does nothing
        check loadNodeState(tmpDir).isNone

      block:
        let
          chainOnline = initTestChain(genesisBlk, forkChoiceRule = ForkChoiceRule.Online)
          bp = BlockProcessor.new(chainOnline)
          lifecycle = ForkChoiceLifecycle.new(bp, tmpDir)
        check lifecycle.canProposeBlocks
        await lifecycle.stop()
        # In Online mode, stop persists node_state.json
        let saved = loadNodeState(tmpDir).get
        check saved.libBlockId == bp.consensus.latestImmutableId

  asyncTest "start and stop manages heartbeat and prolonged bootstrap timers safely in Bootstrap mode":
    let
      genesisBlk = testGenesisBlock()
      chain = initTestChain(genesisBlk, forkChoiceRule = ForkChoiceRule.Bootstrap)
    withTempDir(tmpDir, "test_lifecycle_stop"):
      let
        bp = BlockProcessor.new(chain)
        lifecycle = ForkChoiceLifecycle.new(bp, tmpDir, prolongedBootstrapDuration = ProlongedBootstrapDuration)
      lifecycle.start()
      check not lifecycle.canProposeBlocks

      lifecycle.onSyncComplete()
      check not lifecycle.canProposeBlocks

      await lifecycle.stop()
      check:
        # Processor remains in Bootstrap because timer was cancelled before expiry
        bp.consensus.forkChoiceRule == ForkChoiceRule.Bootstrap
        not lifecycle.canProposeBlocks
        # Persist in Bootstrap mode does not write state
        loadNodeState(tmpDir).isNone

  asyncTest "start and stop in Online mode runs heartbeat and persists on stop":
    let
      genesisBlk = testGenesisBlock()
      chain = initTestChain(genesisBlk, forkChoiceRule = ForkChoiceRule.Online)
    withTempDir(tmpDir, "test_lifecycle_stop_online"):
      let
        bp = BlockProcessor.new(chain)
        lifecycle = ForkChoiceLifecycle.new(bp, tmpDir)
      check lifecycle.canProposeBlocks
      lifecycle.start()

      await lifecycle.stop()
      check loadNodeState(tmpDir).get.libBlockId == bp.consensus.latestImmutableId

{.pop.}
