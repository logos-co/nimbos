# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

## Stateless structural checks of Bedrock `valid_header(B)`. The stateful
## half (parent linkage, slot ordering, wallclock bound, leader proof) is
## owned by the `Chain.tryApplyBlock` composition: ledger `prepareUpdate`
## plus `LocalTree.addBlockToTree`.
## Spec: [1.1.1 Block Construction, Validation and Execution](https://nomos-tech.notion.site/1-1-1-Block-Construction-Validation-and-Execution-269261aa09df807185a9e0764acffe22)

{.push raises: [], gcsafe.}

import
  results,
  ./local_tree,
  ../mempool,
  ../ledger/ledger,
  libp2p/crypto/ed25519/ed25519

from ./types import
  Block, Header, Proposal, References, createBlockRoot, ExpectedBedrockVersion,
  MaxBlockSize, header, blockId, Hash32
from ./mantle/primitives import MaxBlockTxs, SlotNumber
from ./mantle/tx_types import SignedMantleTx, encodeSignedMantleTx

func txBytesLen(txs: openArray[SignedMantleTx]): int =
  ## The block body is the serialized transactions only; neither the header
  ## nor the block signature counts toward `MaxBlockSize`.
  var total = 0
  for stx in txs:
    total += encodeSignedMantleTx(stx).len
  total

func validateBlockHeader(blk: Block): bool =
  if header(blk).bedrockVersion != ExpectedBedrockVersion:
    return false

  # Both bounds are inclusive: a block sitting exactly on the limit is valid.
  if txBytesLen(blk.txs) > MaxBlockSize:
    return false

  if blk.txs.len > MaxBlockTxs:
    return false

  if createBlockRoot(blk.txs) != header(blk).blockRoot:
    return false

  true

func validateBlockBody(blk: Block): bool =
  discard blk # TODO: body checks (header signature)
  true

func validateBlock*(blk: Block): bool =
  validateBlockHeader(blk) and validateBlockBody(blk)

type
  ProposalValidationError* = enum
    MissingReference
    InvalidBlockStructure
    TreeAdmissionRejected
    HeaderRejected
    TransactionsRejected

  BlockValidationErrorKind* {.pure.} = enum
    InvalidBlockStructure
    TreeAdmissionRejected
    HeaderRejected
    TransactionsRejected

  BlockValidationError* = object
    case kind*: BlockValidationErrorKind
    of BlockValidationErrorKind.HeaderRejected, BlockValidationErrorKind.TransactionsRejected:
      ledgerError*: LedgerError
    else:
      discard

func reconstructBlock*(
    proposal: Proposal,
    mempool: Mempool
): Result[Block, ProposalValidationError] =
  ## Reconstructs the block from proposal references using the mempool.
  ## Returns error if any reference is missing or if we cannot retrieve it.
  var txs: seq[SignedMantleTx]
  for r in proposal.references:
    if r == static(default(Hash32)):
      continue
    let tx = mempool.get(r).valueOr:
      return err(MissingReference)
    txs.add(tx)
  
  ok(Block(
    header: proposal.header,
    signature: proposal.signature,
    txs: txs
  ))

proc validateBlockAndTransactions*(
    blk: Block,
    localTree: LocalTree,
    ledger: Ledger[BlockId],
): Result[tuple[id: BlockId, state: LedgerState], BlockValidationError] =
  ## Performs stateless structural checks, localTree tip extension verification,
  ## and stateful ledger validation (Proof of Leadership and Mantle txs).
  if not validateBlock(blk):
    return err(BlockValidationError(kind: BlockValidationErrorKind.InvalidBlockStructure))
  if not localTree.canExtend(blk.header):
    return err(BlockValidationError(kind: BlockValidationErrorKind.TreeAdmissionRejected))
    
  let
    parent = ledger.state(blk.header.parentBlock).valueOr:
      return err(BlockValidationError(kind: BlockValidationErrorKind.TreeAdmissionRejected))
    afterHeader = parent.tryApplyHeader(blk.header.slot, blk.header.proofOfLeadership, ledger.config).valueOr:
      return err(BlockValidationError(kind: BlockValidationErrorKind.HeaderRejected, ledgerError: error))
    afterTxs = afterHeader.tryApplyTxns(blk.txs, blk.header.slot).valueOr:
      return err(BlockValidationError(kind: BlockValidationErrorKind.TransactionsRejected, ledgerError: error))
      
  ok((id: blockId(blk.header), state: afterTxs))

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
      return err(InvalidBlockStructure)
    of BlockValidationErrorKind.TreeAdmissionRejected:
      return err(TreeAdmissionRejected)
    of BlockValidationErrorKind.HeaderRejected:
      return err(HeaderRejected)
    of BlockValidationErrorKind.TransactionsRejected:
      return err(TransactionsRejected)
  ok(blk)

{.pop.}
