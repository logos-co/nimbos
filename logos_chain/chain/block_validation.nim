# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Stateless structural checks of Bedrock block header and body. The stateful
## half is checked via `tryApplyHeader` and `tryApplyTxns` in `ledger.nim`,
## and orchestrated via `validateBlockAndTransactions` in this file.
## Spec: [Cryptarchia v1 — Block Header Validation](https://github.com/logos-co/logos-lips/blob/master/docs/blockchain/raw/cryptarchia-v1-protocol.md#block-header-validation)
## Spec: [Bedrock v1.1 — Block Proposal Validation](https://github.com/logos-co/logos-lips/blob/master/docs/blockchain/raw/bedrock-v1.1-block-construction.md#block-proposal-validation)
## Spec: [Bedrock v1.1 — Mantle Specification: Validation](https://github.com/logos-co/logos-lips/blob/master/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md#validation)

{.push raises: [], gcsafe.}

import
  results,
  libp2p/crypto/ed25519/ed25519,
  ../core/local_tree,
  ../ledger/ledger

from ../core/types import
  Block, Header, Proposal, References, createBlockRoot, ExpectedBedrockVersion,
  MaxBlockSize, header, blockId, Hash32
from ../core/mantle/primitives import MaxBlockTxs, SlotNumber
from ../core/mantle/tx_types import SignedMantleTx, encodeSignedMantleTx

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
    
  let id = blockId(blk.header)
  let prepared = ledger.prepareUpdate(
    id, blk.header.parentBlock, blk.header.slot, blk.header.proofOfLeadership, blk.txs
  ).valueOr:
    if error == LedgerError.ParentNotFound:
      return err(BlockValidationError(kind: BlockValidationErrorKind.TreeAdmissionRejected))
    elif error in {LedgerError.InvalidSlot, LedgerError.InvalidProof}:
      return err(BlockValidationError(kind: BlockValidationErrorKind.HeaderRejected, ledgerError: error))
    else:
      return err(BlockValidationError(kind: BlockValidationErrorKind.TransactionsRejected, ledgerError: error))
      
  ok(prepared)

{.pop.}
