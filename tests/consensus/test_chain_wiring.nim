# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## End-to-end epoch wiring against the real devnet deployment settings:
## settings → LedgerConfig, genesis block → ceremony seed, and a seeded
## genesis ledger state (exercising the f = 1/20 lottery constants on the
## actual devnet configuration).

# `gcsafe` deliberately omitted: `parseDeploymentSettings` (YAML) is not
# GC-safe, matching `tests/core/test_devnet_genesis_mantle_tx.nim`.
{.push raises: [].}
{.used.}

import
  std/[os, strutils],
  unittest2,
  stew/io2,
  ../testutil,
  ../../logos_chain/chain/chain,
  ../../logos_chain/deployment/deployment_settings

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  deploymentSettingsPath = testsDir / "../../config/deployment-settings.yaml"

suite "chain/epoch wiring (devnet deployment settings)":
  setup:
    let
      dsText = readAllChars(deploymentSettingsPath).valueOr:
        check false
        return
      ds = parseDeploymentSettings(dsText).valueOr:
        check false
        return

  test "ledgerConfig derives the devnet schedule":
    let cfg = ledgerConfig(ds)
    check:
      # k = 30, f = 1/20 → base period 600, epoch length 6000, TSI window 3600
      cfg.epochSchedule.basePeriodLength == 600
      cfg.epochSchedule.epochLength == 6000
      cfg.epochSchedule.nonceContributionPeriod == 3600
      cfg.slotActivationCoeff == NonNegativeRatio(num: 1, den: 20)
      cfg.stakeInferenceLearningRate == NonNegativeRatio(num: 5, den: 10)

  test "cryptarchiaParameter decodes the devnet ceremony values":
    let param = ds.cryptarchia.genesisState.cryptarchiaParameter().valueOr:
      check false
      return
    check:
      param.genesisTime == 0x69f8a943'u64
      param.epochNonce == default(FieldElement) # devnet ceremony nonce is zero

  test "fromGenesis builds a lottery-ready genesis state":
    let
      param = ds.cryptarchia.genesisState.cryptarchiaParameter().valueOr:
        check false
        return
      state = LedgerState.fromGenesis(
        [ds.cryptarchia.genesisState.signedMantleTx],
        param.epochNonce, ledgerConfig(ds)).valueOr:
        check false
        return
    check:
      # 4 × (100000 + 1 + 100) distribution notes plus the faucet note.
      state.latestUtxos.len == 13
      state.epochs.activeEpoch.epoch == 0
      state.epochs.nextEpoch.epoch == 1
      # faucet-filtered sum: the ~2^64 faucet mint is excluded.
      state.epochs.activeEpoch.totalStake == 400404
      state.epochs.activeEpoch.lottery0 != default(FieldElement)
      state.epochs.activeEpoch.lottery1 != default(FieldElement)
      state.epochs.blockDensity.periodStart == 0
      state.epochs.blockDensity.periodEnd == 3599

  test "Chain.init wires ledger, epoch state and clock from settings":
    let chain = Chain.init(ds).valueOr:
      check false
      return
    let genesisState = chain.ledger.state(
      blockId(chain.genesisBlock.header)).valueOr:
      check false
      return
    check:
      chain.slotConfig.genesisTime == 0x69f8a943'u64
      chain.slotConfig.slotDurationSeconds == 1
      genesisState.latestUtxos.len == 13
      genesisState.epochs.activeEpoch.totalStake == 400404
      genesisState.epochs.nextEpoch.epoch == 1
      chain.currentWallclockSlot() > 0 # devnet genesis lies in the past

  test "tryApplyBlock ingests a child of genesis end-to-end":
    var chain = Chain.init(ds).valueOr:
      check false
      return
    let
      gid = blockId(chain.genesisBlock.header)
      b1 = childBlock(chain.genesisBlock.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
    check:
      chain.tryApplyBlock(b1).isOk
      chain.ledger.state(id1).isSome
      chain.localTree.localTipId == id1
    let dup = chain.tryApplyBlock(b1)
    check dup.isErr and dup.error.kind == BlockApplyErrorKind.AlreadyApplied

  test "tryApplyBlock rejects a slot beyond the wallclock":
    var chain = Chain.init(ds).valueOr:
      check false
      return
    let
      gid = blockId(chain.genesisBlock.header)
      b1 = childBlock(
        chain.genesisBlock.header, gid, high(SlotNumber) - 1, [])
      r = chain.tryApplyBlock(b1)
    check r.isErr and r.error.kind == BlockApplyErrorKind.FutureSlot

  test "tryApplyBlock reports an unknown parent from the ledger":
    var chain = Chain.init(ds).valueOr:
      check false
      return
    var fakeParent: BlockId
    fakeParent[0] = 7'u8
    let
      orphan = childBlock(
        chain.genesisBlock.header, fakeParent, SlotNumber(1), [])
      r = chain.tryApplyBlock(orphan)
    check:
      r.isErr
      r.error.kind == BlockApplyErrorKind.LedgerRejected
      r.error.ledgerError == LedgerError.ParentNotFound

{.pop.}
