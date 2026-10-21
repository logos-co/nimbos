# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  results,
  chronos,
  ../../../logos_chain/consensus/consensus_state,
  ../../../logos_chain/sync/syncer

suite "sync/syncer (determineStartupForkChoiceRule)":
  test "Offline grace period is 20 minutes":
    check OfflineGracePeriodDuration == 20.minutes
    check ProlongedBootstrapDuration == 24.hours

  test "Explicit --bootstrap flag always yields Bootstrap rule":
    # Even if LIB is advanced and offline duration is 0, explicit flag overrides
    check determineStartupForkChoiceRule(
      explicitBootstrapFlag = true,
      isLibAtGenesis = false,
      lastOnlineTimestampUnix = Opt.some(1000'u64),
      currentTimestampUnix = 1010'u64,
    ) == ForkChoiceRule.Bootstrap

  test "Genesis LIB yields Bootstrap rule":
    check determineStartupForkChoiceRule(
      explicitBootstrapFlag = false,
      isLibAtGenesis = true,
      lastOnlineTimestampUnix = Opt.some(1000'u64),
      currentTimestampUnix = 1010'u64,
    ) == ForkChoiceRule.Bootstrap

  test "Missing last online timestamp yields Bootstrap rule":
    check determineStartupForkChoiceRule(
      explicitBootstrapFlag = false,
      isLibAtGenesis = false,
      lastOnlineTimestampUnix = Opt.none(uint64),
      currentTimestampUnix = 1010'u64,
    ) == ForkChoiceRule.Bootstrap

  test "Restarting within 20-minute grace period yields Online rule":
    const t0 = 1_000_000'u64
    # 5 minutes offline (300s <= 1200s) -> Online
    check determineStartupForkChoiceRule(
      explicitBootstrapFlag = false,
      isLibAtGenesis = false,
      lastOnlineTimestampUnix = Opt.some(t0),
      currentTimestampUnix = t0 + 300'u64,
    ) == ForkChoiceRule.Online

    # Exactly 20 minutes offline (1200s <= 1200s) -> Online
    check determineStartupForkChoiceRule(
      explicitBootstrapFlag = false,
      isLibAtGenesis = false,
      lastOnlineTimestampUnix = Opt.some(t0),
      currentTimestampUnix = t0 + 1200'u64,
    ) == ForkChoiceRule.Online

  test "Restarting after grace period (> 20 min) yields Bootstrap rule":
    const t0 = 1_000_000'u64
    # 20 minutes and 1 second offline (1201s > 1200s) -> Bootstrap
    check determineStartupForkChoiceRule(
      explicitBootstrapFlag = false,
      isLibAtGenesis = false,
      lastOnlineTimestampUnix = Opt.some(t0),
      currentTimestampUnix = t0 + 1201'u64,
    ) == ForkChoiceRule.Bootstrap

    # 1 hour offline (3600s > 1200s) -> Bootstrap
    check determineStartupForkChoiceRule(
      explicitBootstrapFlag = false,
      isLibAtGenesis = false,
      lastOnlineTimestampUnix = Opt.some(t0),
      currentTimestampUnix = t0 + 3600'u64,
    ) == ForkChoiceRule.Bootstrap

  test "Clock skew / instantaneous restart within grace period yields Online rule":
    const t0 = 1_000_000'u64
    # currentTimestampUnix < lastOnlineTimestampUnix -> safe Online fallback
    check determineStartupForkChoiceRule(
      explicitBootstrapFlag = false,
      isLibAtGenesis = false,
      lastOnlineTimestampUnix = Opt.some(t0),
      currentTimestampUnix = t0 - 10'u64,
    ) == ForkChoiceRule.Online

{.pop.}
