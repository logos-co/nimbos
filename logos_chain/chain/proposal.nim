# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  results,
  ../core/[local_tree, block_validation],
  ../ledger/ledger,
  ../mempool

from ../core/types import Block, Proposal, Hash32, header, blockId
from ../core/crypto/types import isZero
from ../core/mantle/tx_types import SignedMantleTx

type
  ProposalValidationError* = enum
    MissingReference
    InvalidBlockStructure
    TreeAdmissionRejected
    HeaderRejected
    TransactionsRejected

func reconstructBlock*(
    proposal: Proposal,
    mempool: Mempool
): Result[Block, ProposalValidationError] =
  ## Reconstructs the block from proposal references using the mempool.
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
