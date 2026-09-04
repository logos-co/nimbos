# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

## Bedrock block proposal construction, transaction selection, and reconstruction.
## Spec: [Block Construction, Validation and Execution v1.1.2](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-block-construction.md)
## Spec: [Execution Market v1.1.0](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/execution-market.md)

{.push raises: [], gcsafe.}

import
  std/[deques, tables],
  results,
  libp2p/crypto/ed25519/ed25519,
  ../core/[types, local_tree, mempool],
  ../core/crypto/types,
  ../core/mantle/[gas, primitives, tx_types],
  ../ledger/[balance, ledger, types],
  ./block_validation

const
  TxMaturitySlots* = 3'u64
  MaxConsecutiveCandidateMisses* = 10

type
  ProposalValidationError* {.pure.} = enum
    MissingReference
    InvalidBlockStructure
    TreeAdmissionRejected

proc selectProposalReferences*(
    m: Mempool,
    tipLedgerState: LedgerState,
    cfg: LedgerConfig,
    currentSlot: SlotNumber,
    maxTxs: int = MaxBlockTxs,
    maxBytes: int = MaxBlockSize,
): tuple[references: References, count: int] =
  ## Selects transactions for block proposal according to the Execution Market spec:
  ## https://github.com/logos-co/logos-lips/blob/38916aa474164ac4acd81e62d19715e17626be17/docs/blockchain/raw/execution-market.md
  ## Enforces count (maxTxs), execution gas (MAX_EXECUTION_GAS_PER_BLOCK), and body byte size (maxBytes).
  ## Populates and returns the fixed-size References array and the selected count directly for proposal creation.
  var refs: References
  var count = 0
  var workingLedger = tipLedgerState.advanceEpochAndMarket(currentSlot, cfg).valueOr:
    tipLedgerState
  var cumulativeExecutionGas = Gas(0)
  var cumulativeBytes = 0
  var consecutiveMisses = 0

  let epoch = workingLedger.epochs.activeEpoch.epoch

  for hash in m.queue:
    if count >= maxTxs:
      break

    m.txs.withValue(hash, item):
      if currentSlot < item.addedAtSlot + TxMaturitySlots:
        # Immature transactions are skipped without counting toward consecutive candidate misses
        continue

      # Lazily compute and cache byteSize and execGas on first evaluation
      let txBytes = item.byteSize.valueOr:
        let sz = byteLen(item.tx)
        item.byteSize = Opt.some(sz)
        sz

      let execGas = item.execGas.valueOr:
        let eg = txExecutionGas(item.tx).valueOr:
          continue
        item.execGas = Opt.some(eg)
        eg

      let nextExecutionGas = cumulativeExecutionGas.checkedAdd(execGas).valueOr:
        continue

      if cumulativeBytes + txBytes > maxBytes or
          nextExecutionGas > MAX_EXECUTION_GAS_PER_BLOCK:
        inc consecutiveMisses
        if consecutiveMisses >= MaxConsecutiveCandidateMisses:
          break
        continue

      let (totalCost, _, _) = workingLedger.mandatory_fees(execGas, txBytes).valueOr:
        continue

      var candidate = workingLedger
      let balance = candidate.tryApplyTx(item.tx, epoch, currentSlot, acceptAllPoq).valueOr:
        continue

      if balance.covers(totalCost):
        refs[count] = hash
        inc count
        cumulativeExecutionGas = nextExecutionGas
        cumulativeBytes += txBytes
        workingLedger = move(candidate)
        consecutiveMisses = 0

  (refs, count)

proc constructProposal*(
    m: Mempool,
    tipLedgerState: LedgerState,
    cfg: LedgerConfig,
    currentSlot: SlotNumber,
    parentBlock: BlockId,
    proofOfLeadership: ProofOfLeadership,
    leaderSecKey: EdPrivateKey,
): Proposal =
  ## Full constructor from mempool: selects fee-paying transaction references from the
  ## mempool according to the execution market spec, constructs the header,
  ## signs it with the leader's private key, and produces the Proposal.
  let (refs, count) = m.selectProposalReferences(
    tipLedgerState, cfg, currentSlot
  )
  let h = initHeader(
    bedrockVersion = ExpectedBedrockVersion,
    parentBlock = parentBlock,
    slot = currentSlot,
    txHashes = refs[0 ..< count],
    proofOfLeadership = proofOfLeadership,
  )
  let sig = leaderSecKey.sign(blockId(h))
  initProposal(h, refs, sig)

func reconstructBlock(
    proposal: Proposal,
    mempool: Mempool
): Result[Block, ProposalValidationError] =
  ## Reconstructs the block from proposal references using the mempool (and internal grace cache).
  ## Returns error if any reference is missing or if we cannot retrieve it.
  var txs: seq[SignedMantleTx]
  for r in proposal.references:
    if r.isZero():
      break
    let tx = mempool.get(r).valueOr:
      return err(ProposalValidationError.MissingReference)
    txs.add(SignedMantleTx(tx))
  
  ok(Block(
    header: proposal.header,
    signature: proposal.signature,
    txs: txs
  ))

func toProposalValidationError(err: BlockValidationError): ProposalValidationError =
  case err.kind
  of BlockValidationErrorKind.TreeAdmissionRejected:
    ProposalValidationError.TreeAdmissionRejected
  else:
    ProposalValidationError.InvalidBlockStructure

proc reconstructAndValidateBlock*(
    proposal: Proposal,
    localTree: LocalTree,
    ledger: Ledger[BlockId],
    mempool: Mempool
): Result[Block, ProposalValidationError] =
  ## Attempts block reconstruction from references, validates the reconstructed
  ## block against localTree and ledger admission rules (skipping stateless tx
  ## checks as mempool txs are already valid), and returns the reconstructed Block.
  ## State transition (prepareBlockUpdate) is handled afterwards in the pipeline.
  let blk = ? reconstructBlock(proposal, mempool)
  discard validateBlockAndStatelessTransactions(blk, localTree, ledger, []).valueOr:
    return err(error.toProposalValidationError)
  ok(blk)

{.pop.}
