# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  std/[deques, tables],
  results,
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
    HeaderRejected
    TransactionsRejected

proc selectTxsForProposal*(
    m: Mempool,
    tipLedgerState: LedgerState,
    cfg: LedgerConfig,
    currentSlot: SlotNumber,
    maxTxs: int = MaxBlockTxs,
    maxBytes: int = MaxBlockSize,
): seq[SignedMantleTx] =
  ## Selects transactions for block proposal according to the Execution Market spec:
  ## https://github.com/logos-co/logos-lips/blob/38916aa474164ac4acd81e62d19715e17626be17/docs/blockchain/raw/execution-market.md
  ## Enforces count (maxTxs), execution gas (MAX_EXECUTION_GAS_PER_BLOCK), and body byte size (maxBytes).
  var selected: seq[SignedMantleTx]
  var workingLedger = tipLedgerState.advanceEpochAndMarket(currentSlot, cfg).valueOr:
    tipLedgerState
  var cumulativeExecutionGas = Gas(0)
  var cumulativeBytes = 0
  var consecutiveMisses = 0

  let epoch = workingLedger.epochs.activeEpoch.epoch

  for hash in m.queue:
    if selected.len >= maxTxs:
      break

    m.txs.withValue(hash, item):
      if currentSlot < item[].addedAtSlot + TxMaturitySlots:
        continue

      # Lazily compute and cache byteSize and execGas on first evaluation
      let txBytes = item[].byteSize.valueOr:
        let sz = encodeSignedMantleTx(item[].tx).len
        item[].byteSize = Opt.some(sz)
        sz

      let execGas = item[].execGas.valueOr:
        let eg = txExecutionGas(item[].tx).valueOr:
          continue
        item[].execGas = Opt.some(eg)
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
      let balance = candidate.tryApplyTx(item[].tx, epoch, currentSlot).valueOr:
        continue

      if balance.covers(totalCost):
        selected.add(item[].tx)
        cumulativeExecutionGas = nextExecutionGas
        cumulativeBytes += txBytes
        workingLedger = move(candidate)
        consecutiveMisses = 0

  selected

func reconstructBlock*(
    proposal: Proposal,
    mempool: Mempool
): Result[Block, ProposalValidationError] =
  ## Reconstructs the block from proposal references using the mempool (and internal grace cache).
  ## Returns error if any reference is missing or if we cannot retrieve it.
  var txs: seq[SignedMantleTx]
  for r in proposal.references:
    if r.isZero():
      continue
    let tx = mempool.get(r).valueOr:
      return err(ProposalValidationError.MissingReference)
    txs.add(tx)
  
  ok(Block(
    header: proposal.header,
    signature: proposal.signature,
    txs: txs
  ))

proc reconstructAndValidateProposal*(
    proposal: Proposal,
    localTree: LocalTree,
    ledger: Ledger[BlockId],
    mempool: Mempool
): Result[Block, ProposalValidationError] =
  ## Attempts block reconstruction from references, validates the reconstructed
  ## block against the localTree, and statefully verifies the leader proof and transactions sequence.
  ## Returns the reconstructed Block on success.
  let blk = ? reconstructBlock(proposal, mempool)
  discard validateBlockAndTransactions(blk, localTree, ledger).valueOr:
    case error.kind
    of BlockValidationErrorKind.InvalidBlockStructure:
      return err(ProposalValidationError.InvalidBlockStructure)
    of BlockValidationErrorKind.TreeAdmissionRejected:
      return err(ProposalValidationError.TreeAdmissionRejected)
    of BlockValidationErrorKind.HeaderRejected:
      return err(ProposalValidationError.HeaderRejected)
    of BlockValidationErrorKind.TransactionsRejected:
      return err(ProposalValidationError.TransactionsRejected)
      
  ok(blk)

{.pop.}
