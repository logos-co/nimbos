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
  chronicles,
  results,
  ../core/[local_tree, types],
  ../deployment/deployment_settings,
  ../ledger/[ledger, stake_inference],
  ../mempool,
  ./[block_validation, genesis]

export genesis, local_tree, mempool, block_validation
export ledger except config

const DefaultSecurityParam*: uint64 = 1'u64

type
  Chain* = object
    genesisBlock*: Block
    localTree*: LocalTree
    ledger*: Ledger[BlockId]
    mempool*: Mempool
    slotConfig*: SlotConfig
    securityParam*: uint64

  BlockApplyErrorKind* {.pure.} = enum
    AlreadyApplied
    FutureSlot
    InvalidStructure
    MissingParent
    UnviableFork
    LedgerRejected
    StatelessTxRejected

  BlockApplyError* = object
    case kind*: BlockApplyErrorKind
    of BlockApplyErrorKind.LedgerRejected:
      ledgerError*: LedgerError
    of BlockApplyErrorKind.StatelessTxRejected:
      statelessError*: StatelessLedgerError
    else:
      discard

func `$`*(e: BlockApplyError): string =
  case e.kind
  of BlockApplyErrorKind.LedgerRejected: "ledger: " & $e.ledgerError
  of BlockApplyErrorKind.StatelessTxRejected: "stateless tx: " & $e.statelessError
  else: $e.kind

func isRecoverable*(kind: BlockApplyErrorKind): bool =
  ## True when the same block may still apply later without any change to it.
  case kind
  of BlockApplyErrorKind.AlreadyApplied, BlockApplyErrorKind.FutureSlot,
      BlockApplyErrorKind.MissingParent:
    true
  of BlockApplyErrorKind.InvalidStructure, BlockApplyErrorKind.UnviableFork,
      BlockApplyErrorKind.LedgerRejected, BlockApplyErrorKind.StatelessTxRejected:
    false

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
    securityParam: uint64 = DefaultSecurityParam,
): T =
  let secParam = max(securityParam, DefaultSecurityParam)
  T(
    genesisBlock: genesisBlock,
    localTree: newLocalTree(genesisBlock, secParam),
    ledger: ledger,
    mempool: Mempool.init(maxMempoolCapacity(secParam)),
    slotConfig: slotConfig,
    securityParam: secParam,
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
      slotDurationSeconds: uint64(settings.time.slotDuration.seconds)),
    securityParam = uint64(settings.cryptarchia.securityParam)))

proc currentWallclockSlot*(chain: Chain): SlotNumber =
  ## Slot containing the current system time.
  wallclockSlot(uint64(max(getTime().toUnix(), 0'i64)), chain.slotConfig)

proc readdBranchTxs(chain: var Chain, fromId, toId: BlockId) =
  let nowSlot = chain.currentWallclockSlot()
  var curr = fromId
  while not curr.isZero and curr != toId:
    let b = chain.localTree.getBlock(curr).valueOr:
      warn "Missing block during reorg transaction re-addition",
          missingBlockId = curr, toId = toId
      break
    for stx in b.txs:
      discard chain.mempool.add(ValidSignedMantleTx(stx), nowSlot)
    curr = header(b).parentBlock

proc removeBranchTxs(chain: var Chain, fromId, toId: BlockId) =
  var curr = fromId
  while not curr.isZero and curr != toId:
    let b = chain.localTree.getBlock(curr).valueOr:
      warn "Missing block during reorg transaction removal",
          missingBlockId = curr, toId = toId
      break
    chain.mempool.pruneBlockTxs(b)
    curr = header(b).parentBlock

proc pruneStatesBeforeLib(chain: var Chain, newLibId, oldLibId: BlockId) =
  ## Prunes canonical ledger states strictly older than the new immutable block (LIB).
  ## The state at `newLibId` is retained as the finalized base anchor.
  let newLib = chain.localTree.getBlock(newLibId).valueOr:
    return
  var curr = header(newLib).parentBlock
  while not curr.isZero:
    discard chain.ledger.pruneStateAt(curr)
    if curr == oldLibId:
      break
    let blk = chain.localTree.getBlock(curr).valueOr:
      break
    curr = header(blk).parentBlock

proc tryApplyBlock*(
    chain: var Chain, blk: Block): Result[void, BlockApplyError] =
  ## Full block ingestion in `valid_header` order.
  template hdr: auto = header(blk)
  let id = blockId(hdr)
  if chain.ledger.hasState(id):
    return err(BlockApplyError(kind: AlreadyApplied))
  if hdr.slot > chain.currentWallclockSlot():
    return err(BlockApplyError(kind: FutureSlot))
  let unverified = chain.mempool.unverifiedTxs(blk.txs)
  let prepared = prepareBlockUpdate(blk, chain.localTree, chain.ledger, unverified).valueOr:
    case error.kind
    of BlockValidationErrorKind.InvalidBlockStructure:
      return err(BlockApplyError(kind: InvalidStructure))
    of BlockValidationErrorKind.MissingParent:
      return err(BlockApplyError(kind: MissingParent))
    of BlockValidationErrorKind.UnviableFork:
      return err(BlockApplyError(kind: UnviableFork))
    of BlockValidationErrorKind.HeaderRejected,
        BlockValidationErrorKind.TransactionsRejected:
      return err(BlockApplyError(kind: LedgerRejected, ledgerError: error.ledgerError))
    of BlockValidationErrorKind.StatelessTxRejected:
      return err(BlockApplyError(kind: StatelessTxRejected, statelessError: error.statelessError))

  let oldTip = chain.localTree.localTipId()
  if not chain.localTree.addBlockToTree(blk):
    return err(BlockApplyError(kind: UnviableFork))
  chain.ledger.commitUpdate(prepared.id, prepared.state)
  let newTip = chain.localTree.localTipId()

  if newTip != oldTip:
    # Active tip advanced: handles both normal block extensions (lcaId == oldTip)
    # and multi-block fork reorganizations (lcaId == common ancestor).
    let (lcaId, _) = chain.localTree.lcaBlockIdAndHeight(
      oldTip, newTip
    ).expect("LCA must exist between active tree tips")
    # 1. readd before remove: if a transaction exists in both branches, readding first allows removing it next.
    # 2. tryUpdateLib after mempool reorg: ensures fork pruning does not delete orphaned blocks before transactions are restored.
    # 3. Prune fork states and canonical states older than the new immutable block (retaining latestImmutableId as anchor).
    chain.readdBranchTxs(oldTip, lcaId)
    chain.removeBranchTxs(newTip, lcaId)
    let oldLibId = chain.localTree.latestImmutableBlockId()
    let prunedBlockIds = chain.localTree.tryUpdateLib()
    for prunedId in prunedBlockIds:
      discard chain.ledger.pruneStateAt(prunedId)
    let newLibId = chain.localTree.latestImmutableBlockId()
    if newLibId != oldLibId:
      chain.pruneStatesBeforeLib(newLibId, oldLibId)

  chain.mempool.pruneExpiredTxs(chain.currentWallclockSlot())
  ok()
