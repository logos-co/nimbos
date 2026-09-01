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
  ../ledger/[ledger, stake_inference],
  ./block_validation,
  ./genesis

export genesis, local_tree
export ledger except config

type
  Chain* = object
    genesisBlock*: Block
    localTree*: LocalTree
    ledger*: Ledger[BlockId]
    slotConfig*: SlotConfig

  BlockApplyErrorKind* {.pure.} = enum
    AlreadyApplied
    FutureSlot
    InvalidStructure
    TreeRejected
    LedgerRejected

  BlockApplyError* = object
    case kind*: BlockApplyErrorKind
    of BlockApplyErrorKind.LedgerRejected:
      ledgerError*: LedgerError
    else:
      discard

func `$`*(e: BlockApplyError): string =
  case e.kind
  of BlockApplyErrorKind.LedgerRejected: "ledger: " & $e.ledgerError
  else: $e.kind

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
    learningRateFixed: fixedPoint(c.learningRate),
    faucetPk: Opt.some(c.genesisState.faucetZkPublicKey))

func init*(
    T: type Chain,
    genesisBlock: Block,
    ledger: Ledger[BlockId],
    slotConfig: SlotConfig,
    latestImmutableHeight: uint64 = 0,
): T =
  T(
    genesisBlock: genesisBlock,
    localTree: newLocalTree(genesisBlock, latestImmutableHeight),
    ledger: ledger,
    slotConfig: slotConfig,
  )

proc init*(
    T: type Chain,
    settings: DeploymentSettings,
    leaderProofVerifier: LeaderProofVerifier = verifyLeaderProof,
): Result[T, string] =
  let
    genesisBlock = createGenesisBlock(settings.cryptarchia.genesisState.signedMantleTx)
    cfg = ledgerConfig(settings)
    sdp = SdpRegistry.init(
      settings.cryptarchia.sdpConfig,
      blendRewardsParams(settings, cfg.epochSchedule.epochLength))
    param = settings.cryptarchia.genesisState.cryptarchiaParameter().valueOr:
      return err("chain: " & $error)
    genesisState = LedgerState.fromGenesis(
        genesisBlock.txs, param.epochNonce, sdp, cfg).valueOr:
      return err("chain: failed to build the genesis state: " & $error)
  ok(T.init(
    genesisBlock,
    Ledger[BlockId].init(blockId(genesisBlock.header), genesisState, cfg, leaderProofVerifier),
    SlotConfig(
      genesisTime: param.genesisTime,
      slotDurationSeconds: uint64(settings.time.slotDuration.seconds))))

proc currentWallclockSlot*(chain: Chain): SlotNumber =
  ## Slot containing the current system time.
  wallclockSlot(uint64(max(getTime().toUnix(), 0'i64)), chain.slotConfig)

proc tryApplyBlock*(
    chain: var Chain, blk: Block): Result[void, BlockApplyError] =
  ## Full block ingestion in `valid_header` order.
  template hdr: auto = header(blk)
  let id = blockId(hdr)
  if chain.ledger.state(id).isSome:
    return err(BlockApplyError(kind: AlreadyApplied))
  if hdr.slot > chain.currentWallclockSlot():
    return err(BlockApplyError(kind: FutureSlot))
  let prepared = prepareBlockUpdate(blk, chain.localTree, chain.ledger).valueOr:
    case error.kind
    of BlockValidationErrorKind.InvalidBlockStructure:
      return err(BlockApplyError(kind: InvalidStructure))
    of BlockValidationErrorKind.TreeAdmissionRejected:
      return err(BlockApplyError(kind: TreeRejected))
    of BlockValidationErrorKind.HeaderRejected,
        BlockValidationErrorKind.TransactionsRejected:
      return err(BlockApplyError(kind: LedgerRejected, ledgerError: error.ledgerError))
  if not chain.localTree.addBlockToTree(blk):
    return err(BlockApplyError(kind: TreeRejected))
  chain.ledger.commitUpdate(prepared.id, prepared.state)
  ok()

{.pop.}
