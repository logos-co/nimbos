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
  ./local_tree,
  ../core/types,
  ../deployment/deployment_settings,
  ../ledger/[ledger, stake_inference],
  ../mempool,
  ./[block_validation, genesis, orphan_pool, proposal, uncle_validation]

export types, genesis, local_tree, mempool, block_validation, orphan_pool, proposal,
  uncle_validation
export ledger except config

const DefaultSecurityParam*: uint64 = 1'u64

type
  Chain* = object
    genesisBlock*: ValidBlock
    localTree*: LocalTree
    ledger*: Ledger[BlockId]
    mempool*: Mempool
    slotConfig*: SlotConfig
    securityParam*: uint64
    orphanPool*: OrphanPool

  BlockApplyErrorKind* {.pure.} = enum
    AlreadyApplied
    InFlight
    FutureSlot
    InvalidStructure
    MissingReference
    UnviableFork
    LedgerRejected
    StatelessTxRejected
    OrphanBuffered
    OrphanAlreadyBuffered
    UncleRejected

  BlockApplyError* = object
    case kind*: BlockApplyErrorKind
    of BlockApplyErrorKind.LedgerRejected:
      ledgerError*: LedgerError
    of BlockApplyErrorKind.StatelessTxRejected:
      statelessError*: StatelessLedgerError
    of BlockApplyErrorKind.UncleRejected:
      uncleError*: UncleError
    else:
      discard

func `$`*(e: BlockApplyError): string =
  case e.kind
  of BlockApplyErrorKind.LedgerRejected: "ledger: " & $e.ledgerError
  of BlockApplyErrorKind.StatelessTxRejected: "stateless tx: " & $e.statelessError
  of BlockApplyErrorKind.UncleRejected: "uncle: " & $e.uncleError
  else: $e.kind

func isRecoverable*(kind: BlockApplyErrorKind): bool =
  ## True when the same block may still apply later without any change to it.
  case kind
  of BlockApplyErrorKind.AlreadyApplied, BlockApplyErrorKind.InFlight,
      BlockApplyErrorKind.FutureSlot, BlockApplyErrorKind.OrphanBuffered,
      BlockApplyErrorKind.OrphanAlreadyBuffered,
      BlockApplyErrorKind.MissingReference:
    true
  of BlockApplyErrorKind.InvalidStructure, BlockApplyErrorKind.UnviableFork,
      BlockApplyErrorKind.LedgerRejected, BlockApplyErrorKind.StatelessTxRejected,
      BlockApplyErrorKind.UncleRejected:
    false

func ledgerConfig*(settings: DeploymentSettings): LedgerConfig =
  ## Epoch-machinery configuration from validated deployment settings
  ## (schedule arithmetic requires positive `security_param`, phases, `f`).
  let c = settings.cryptarchia
  LedgerConfig(
    epochSchedule: EpochSchedule(
      basePeriodLength:
        slotsForBlocks(uint64(c.securityParam), c.slotActivationCoeff),
      stakeDistributionStabilization:
        uint64(c.epochConfig.epochStakeDistributionStabilization),
      nonceBuffer: uint64(c.epochConfig.epochPeriodNonceBuffer),
      nonceStabilization: uint64(c.epochConfig.epochPeriodNonceStabilization)),
    slotActivationCoeff: c.slotActivationCoeff,
    learningRateFixed: fixedPoint(c.learningRate),
    faucetPk: Opt.some(c.genesisState.faucetZkPublicKey),
    uncleWindowSlots:
      slotsForBlocks(uint64(c.uncleReferenceWindowInBlock), c.slotActivationCoeff))

func init*(
    T: type Chain,
    genesisBlock: ValidBlock,
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
    orphanPool: OrphanPool(),
  )

proc init*(
    T: type Chain,
    settings: DeploymentSettings,
    leaderProofVerifier: LeaderProofVerifier = verifyLeaderProof,
    poqVerifier: ProofOfQuotaVerifier = verifyProofOfQuota,
): Result[T, string] =
  let
    validGenesisTx = settings.cryptarchia.genesisState.validGenesisTx
    param = cryptarchiaParameter(validGenesisTx).valueOr:
      return err("chain: " & $error)
    genesisBlock = createGenesisBlock(validGenesisTx)
  # A stale body_root in the settings file must fail at start-up, not later.
  if genesisBlock.header != settings.cryptarchia.genesisState.header:
    return err(
      "chain: genesis header in deployment settings does not match the genesis transaction")
  let
    cfg = ledgerConfig(settings)
    sdp = SdpRegistry.init(
      settings.cryptarchia.sdpConfig,
      blendRewardsParams(settings, cfg.epochSchedule.epochLength))
    genesisState = LedgerState.fromGenesis(
        validGenesisTx, param.epochNonce, sdp, cfg).valueOr:
      return err("chain: failed to build the genesis state: " & $error)
  ok(T.init(
    genesisBlock,
    Ledger[BlockId].init(
      blockId(genesisBlock.header), genesisState, cfg, leaderProofVerifier,
      poqVerifier),
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
    for vtx in b.txs:
      discard chain.mempool.add(vtx, nowSlot)
    curr = header(b).parentBlock

proc removeBranchTxs(chain: var Chain, fromId, toId: BlockId) =
  var curr = fromId
  while not curr.isZero and curr != toId:
    let b = chain.localTree.getBlock(curr).valueOr:
      warn "Missing block during reorg transaction removal",
          missingBlockId = curr, toId = toId
      break
    chain.mempool.pruneTxs(b.txs)
    curr = header(b).parentBlock

proc pruneStatesBeforeLib(chain: var Chain, newLibId, oldLibId: BlockId) =
  ## Prunes canonical ledger states strictly older than the new immutable block (LIB).
  ## The state at `newLibId` is retained as the finalized base anchor.
  let newLib = chain.localTree.getBlock(newLibId).valueOr:
    return
  var curr = header(newLib).parentBlock
  while not curr.isZero:
    chain.ledger.pruneStateAt(curr)
    if curr == oldLibId:
      break
    let blk = chain.localTree.getBlock(curr).valueOr:
      break
    curr = header(blk).parentBlock

proc handleTipChange(chain: var Chain, oldTip, newTip: BlockId) =
  if newTip == oldTip:
    return
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
  let
    oldLibId = chain.localTree.latestImmutableBlockId()
    prunedBlockIds = chain.localTree.tryUpdateLib()
  for prunedId in prunedBlockIds:
    chain.ledger.pruneStateAt(prunedId)
  let newLibId = chain.localTree.latestImmutableBlockId()
  if newLibId != oldLibId:
    chain.pruneStatesBeforeLib(newLibId, oldLibId)
    chain.orphanPool.pruneIncompatibleWithImmutable(chain.localTree)

func toBlockApplyError*(err: BlockValidationError): BlockApplyError =
  case err.kind
  of BlockValidationErrorKind.InvalidBlockStructure:
    BlockApplyError(kind: InvalidStructure)
  of BlockValidationErrorKind.UnviableFork:
    BlockApplyError(kind: UnviableFork)
  of BlockValidationErrorKind.HeaderRejected,
      BlockValidationErrorKind.TransactionsRejected:
    BlockApplyError(kind: LedgerRejected, ledgerError: err.ledgerError)
  of BlockValidationErrorKind.StatelessTxRejected:
    BlockApplyError(kind: StatelessTxRejected, statelessError: err.statelessError)

func checkViability(
    chain: Chain, hdr: Header, curSlot: SlotNumber
): Result[BlockId, BlockApplyError] =
  let id = blockId(hdr)
  # The tree keeps applied blocks whose states were pruned below the LIB.
  if chain.localTree.hasBlock(id):
    return err(BlockApplyError(kind: AlreadyApplied))
  if chain.orphanPool.hasOrphan(id):
    return err(BlockApplyError(kind: OrphanAlreadyBuffered))
  # Slots increase along a chain, so a block at or before the LIB slot cannot
  # descend from the LIB. Holds without the parent, which pruning may remove.
  if hdr.slot <= chain.localTree.latestImmutableSlot():
    return err(BlockApplyError(kind: UnviableFork))
  if hdr.slot > curSlot:
    return err(BlockApplyError(kind: FutureSlot))
  ok(id)

proc applyValidBlock(
    chain: var Chain,
    validBlk: ValidBlock,
    headerState: LedgerState,
    id: BlockId,
    curSlot: SlotNumber,
): Result[void, BlockApplyError] =
  let preparedState = prepareBlockUpdate(validBlk, chain.ledger, headerState).valueOr:
    chain.orphanPool.pruneDescendants(id)
    return err(BlockApplyError(kind: LedgerRejected, ledgerError: error.ledgerError))
  let oldTip = chain.localTree.localTipId()

  if not chain.localTree.addBlockToTree(validBlk):
    chain.orphanPool.pruneDescendants(id)
    return err(BlockApplyError(kind: UnviableFork))
  chain.ledger.commitUpdate(id, preparedState)
  let newTip = chain.localTree.localTipId()
  chain.handleTipChange(oldTip, newTip)
  chain.mempool.pruneExpiredTxs(curSlot)
  ok()

proc applyAdmittedBlock(
    chain: var Chain,
    admittedBlk: AdmittedBlock,
    id: BlockId,
    curSlot: SlotNumber,
): Result[void, BlockApplyError] =
  # Tier 3: PoL against parent state and stateless transaction validation (mempool fast path)
  let
    (validBlk, headerState) = validatePolAndStatelessTransactions(
      admittedBlk, chain.ledger, chain.mempool
    ).valueOr:
      chain.orphanPool.pruneDescendants(id)
      return err(toBlockApplyError(error))
  # Step 10 runs after the PoL of the block. The order does not change the
  # verdict. A sender without stake fails the PoL at one proof check, before
  # the node pays up to `MaxUncles` signature and proof checks for its uncles.
  validateUncles(admittedBlk, chain.localTree, chain.ledger).isOkOr:
    chain.orphanPool.pruneDescendants(id)
    return err(BlockApplyError(kind: UncleRejected, uncleError: error))
  chain.applyValidBlock(validBlk, headerState, id, curSlot)

type
  TopologyStatus* {.pure.} = enum
    ParentPresent
    Orphan

proc admitOrBuffer(
    chain: var Chain,
    status: TopologyStatus,
    admittedBlk: AdmittedBlock,
    id: BlockId,
    curSlot: SlotNumber,
): Result[void, BlockApplyError] =
  case status
  of TopologyStatus.Orphan:
    if not chain.orphanPool.addOrphan(admittedBlk):
      return err(BlockApplyError(kind: OrphanAlreadyBuffered))
    err(BlockApplyError(kind: OrphanBuffered))
  of TopologyStatus.ParentPresent:
    chain.applyAdmittedBlock(admittedBlk, id, curSlot)

func checkTopology*(
    header: Header,
    localTree: LocalTree,
    ledger: Ledger[BlockId],
): Result[TopologyStatus, BlockApplyError] =
  let missing = not ledger.hasState(header.parentBlock)
  if not missing:
    let parentHdr = localTree.fetchHeader(header.parentBlock).valueOr:
      return err(BlockApplyError(kind: UnviableFork))
    if header.slot <= parentHdr.slot:
      return err(BlockApplyError(kind: InvalidStructure))

  if not localTree.canDescendFromImmutable(header):
    return err(BlockApplyError(kind: UnviableFork))

  ok(if missing: TopologyStatus.Orphan else: TopologyStatus.ParentPresent)

proc tryApplyAdmittedBlock*(
    chain: var Chain,
    admittedBlk: AdmittedBlock,
): Result[void, BlockApplyError] =
  ## Directly applies an admitted block promoted from the orphan pool.
  let
    curSlot = chain.currentWallclockSlot()
    hdr = header(admittedBlk)
    id = chain.checkViability(hdr, curSlot).valueOr:
      chain.orphanPool.pruneDescendants(blockId(hdr))
      return err(error)

  let status = checkTopology(hdr, chain.localTree, chain.ledger).valueOr:
    chain.orphanPool.pruneDescendants(id)
    return err(error)
  if status == TopologyStatus.Orphan:
    chain.orphanPool.pruneDescendants(id)
    return err(BlockApplyError(kind: UnviableFork))

  chain.applyAdmittedBlock(admittedBlk, id, curSlot)

proc tryApplyBlock*(
    chain: var Chain,
    blk: Block,
): Result[void, BlockApplyError] =
  ## Full block ingestion in `valid_header` order, with automatic orphan buffering.
  let
    curSlot = chain.currentWallclockSlot()
    id = ?chain.checkViability(blk.header, curSlot)

  let status = ?checkTopology(blk.header, chain.localTree, chain.ledger)

  let admittedBlk = admitBlock(blk).valueOr:
    return err(toBlockApplyError(error))

  chain.admitOrBuffer(status, admittedBlk, id, curSlot)

proc tryApplyProposal*(
    chain: var Chain,
    proposal: Proposal,
): Result[void, BlockApplyError] =
  ## Privileged proposal ingestion: reconstructs transactions from the mempool,
  ## admits the proposal through Tier 0-2 checks (buffering as orphan if parent is unknown),
  ## and applies the resulting block without redundant stateless tx validation.
  let
    curSlot = chain.currentWallclockSlot()
    id = ?chain.checkViability(proposal.header, curSlot)

  let status = ?checkTopology(proposal.header, chain.localTree, chain.ledger)

  let validTxs = reconstructProposalTxs(proposal, chain.mempool).valueOr:
    case error
    of ProposalValidationError.MissingReference:
      return err(BlockApplyError(kind: BlockApplyErrorKind.MissingReference))

  let admittedBlk = admitProposal(proposal, validTxs).valueOr:
    return err(toBlockApplyError(error))

  chain.admitOrBuffer(status, admittedBlk, id, curSlot)

{.pop.}
