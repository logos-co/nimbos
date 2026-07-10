# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Chain initialization: load deployment settings, build genesis block, seed ledger state.

{.push raises: [], gcsafe.}

import
  std/times,
  results,
  ../core/[types, local_tree],
  ../deployment/deployment_settings,
  ../ledger/ledger,
  ./genesis

export genesis, local_tree
export ledger except config

type
  Chain* = object
    genesisBlock*: Block
    localTree*: LocalTree
    ledger*: Ledger[BlockId]
    genesisTime*: WallclockSeconds ## from the genesis inscription
    slotDurationSeconds*: uint64

func ledgerConfig*(settings: DeploymentSettings): LedgerConfig =
  ## Epoch-machinery configuration from validated deployment settings
  ## (schedule arithmetic requires positive `security_param`, phases, `f`).
  let c = settings.cryptarchia
  LedgerConfig(
    epochSchedule: EpochSchedule(
      basePeriodLength:
        basePeriodLength(uint64(c.securityParam), c.slotActivationCoeff),
      stakeDistributionStabilization:
        uint64(c.epochConfig.epochStakeDistributionStabilization),
      nonceBuffer: uint64(c.epochConfig.epochPeriodNonceBuffer),
      nonceStabilization: uint64(c.epochConfig.epochPeriodNonceStabilization)),
    slotActivationCoeff: c.slotActivationCoeff,
    stakeInferenceLearningRate: c.learningRate)

func seedGenesisEpochs*(
    base: sink LedgerState, settings: DeploymentSettings, cfg: LedgerConfig
): Result[LedgerState, string] =
  ## Seeds epoch bookkeeping on a freshly built genesis ledger state from
  ## the genesis block's ceremony values (nonce, faucet-filtered stake).
  let
    seed = settings.cryptarchia.genesisState.genesisEpochSeed().valueOr:
      return err("chain: " & $error)
    state = base.withGenesisEpochs(seed.nonce, seed.totalStake, cfg).valueOr:
      return err("chain: failed to seed genesis epochs: " & $error)
  ok(state)

func init*(T: type Chain, genesisBlock: Block, ledger: Ledger[BlockId], latestImmutableHeight: uint64 = 0): T =
  T(
    genesisBlock: genesisBlock,
    localTree: newLocalTree(genesisBlock, latestImmutableHeight),
    ledger: ledger,
  )

func init*(T: type Chain, settings: DeploymentSettings): Result[T, string] =
  let
    genesisBlock = createGenesisBlock(settings.cryptarchia.genesisState.signedMantleTx)
    cfg = ledgerConfig(settings)
    let sdp = SdpRegistry.init(settings.cryptarchia.sdpConfig)
    seed = settings.cryptarchia.genesisState.genesisEpochSeed().valueOr:
      return err("chain: " & $error)
    # TODO: apply the genesis transactions once trusted genesis execution
    # (proof checks skipped) lands; until then the UTXO set starts empty
    # with epoch bookkeeping seeded.
    genesisState = LedgerState.fromUtxos([], cfg).withGenesisEpochs(
        seed.nonce, seed.totalStake, cfg).valueOr:
      return err("chain: failed to seed genesis epochs: " & $error)
  var chain = T.init(genesisBlock)
  chain.ledger = Ledger[BlockId].init(
    blockId(genesisBlock.header), genesisState, cfg)
  chain.genesisTime = seed.genesisTime
  chain.slotDurationSeconds = uint64(settings.time.slotDuration.seconds)
  ok(chain)

proc currentWallclockSlot*(chain: Chain): SlotNumber =
  ## Slot containing the current system time; `high(SlotNumber)` (bound
  ## disabled) when the chain has no clock (zero slot duration).
  if chain.slotDurationSeconds == 0:
    return high(SlotNumber)
  wallclockSlot(
    uint64(max(getTime().toUnix(), 0'i64)),
    chain.genesisTime, chain.slotDurationSeconds)

{.pop.}
