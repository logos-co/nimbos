# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Stateless structural checks of Bedrock block header and body. The stateful
## half (parent linkage, slot ordering, wallclock bound, leader proof verification
## called during `tryApplyHeader` in `ledger.nim`) is owned by the `Chain.tryApplyBlock`
## composition: ledger `prepareUpdate` plus `LocalTree.addBlockToTree`.
## Spec: [Block Construction, Validation and Execution v1.1.2](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-block-construction.md)

{.push raises: [], gcsafe.}

import
  results,
  ../core/local_tree,
  ../core/mantle/tx_validation,
  ../ledger/ledger,
  libp2p/crypto/ed25519/ed25519

export tx_validation.StatelessLedgerError

from ../core/types import
  Block, createBlockRoot, ExpectedBedrockVersion, MaxBlockSize, header, blockId
from ../core/mantle/primitives import MaxBlockTxs
from ../core/mantle/tx_types import SignedMantleTx, encodeSignedMantleTx

type
  BlockValidationErrorKind* {.pure.} = enum
    InvalidBlockStructure
    TreeAdmissionRejected
    HeaderRejected
    TransactionsRejected
    StatelessTxRejected

  BlockValidationError* = object
    case kind*: BlockValidationErrorKind
    of BlockValidationErrorKind.HeaderRejected, BlockValidationErrorKind.TransactionsRejected:
      ledgerError*: LedgerError
    of BlockValidationErrorKind.StatelessTxRejected:
      statelessError*: StatelessLedgerError
    else:
      discard

func txBytesLen(txs: openArray[SignedMantleTx]): int =
  var total = 0
  for stx in txs:
    total += encodeSignedMantleTx(stx).len
  total

func validateBlockHeader*(blk: Block): bool =
  let h = header(blk)
  if h.bedrockVersion != ExpectedBedrockVersion:
    return false

  if h.proofOfLeadership.leaderKey == default(Ed25519PublicKey):
    return false

  if h.slot > 0 and h.parentBlock == default(BlockId):
    return false

  if blk.txs.len > 0 and h.blockRoot == default(Hash32):
    return false

  if createBlockRoot(blk.txs) != h.blockRoot:
    return false

  if not verify(blk.signature, blockId(h), h.proofOfLeadership.leaderKey):
    return false

  true

proc validateBlockBody*(blk: Block): Result[void, BlockValidationError] =
  if blk.signature == default(Ed25519Signature):
    return err(BlockValidationError(kind: BlockValidationErrorKind.InvalidBlockStructure))

  if blk.txs.len > MaxBlockTxs:
    return err(BlockValidationError(kind: BlockValidationErrorKind.InvalidBlockStructure))

  ## Do NOT change this evaluation order: per-transaction validation MUST run
  ## before txBytesLen to ensure opcode/payload/proof structures are valid
  ## prior to transaction serialization in encodeSignedMantleTx (preventing
  ## AssertionDefect on malformed input).
  for tx in blk.txs:
    validateMantleTxStateless(tx).isOkOr:
      return err(BlockValidationError(
        kind: BlockValidationErrorKind.StatelessTxRejected,
        statelessError: error,
      ))

  if txBytesLen(blk.txs) > MaxBlockSize:
    return err(BlockValidationError(kind: BlockValidationErrorKind.InvalidBlockStructure))

  ok()

proc validateBlock*(blk: Block): Result[void, BlockValidationError] =
  ## Do NOT change this evaluation order: validateBlockBody MUST run before
  ## validateBlockHeader to ensure transaction count bounds (MaxBlockTxs) and
  ## per-transaction opcode/proof structures are verified prior to Merkle root
  ## construction in validateBlockHeader (preventing AssertionDefect on malformed input).
  ?validateBlockBody(blk)
  if not validateBlockHeader(blk):
    return err(BlockValidationError(kind: BlockValidationErrorKind.InvalidBlockStructure))
  ok()

proc validateBlockAndTransactions*(
    blk: Block,
    localTree: LocalTree,
    ledger: Ledger[BlockId],
): Result[BlockId, BlockValidationError] =
  ## Read-only validation: stateless structural checks, localTree extension,
  ## and parent existence check in the ledger.
  ?validateBlock(blk)
  if not localTree.canExtend(blk.header):
    return err(BlockValidationError(kind: BlockValidationErrorKind.TreeAdmissionRejected))
  if ledger.state(blk.header.parentBlock).isNone:
    return err(BlockValidationError(kind: BlockValidationErrorKind.TreeAdmissionRejected))

  ok(blockId(blk.header))

proc prepareBlockUpdate*(
    blk: Block,
    localTree: LocalTree,
    ledger: Ledger[BlockId],
): Result[tuple[id: BlockId, state: LedgerState], BlockValidationError] =
  ## Validates block admission and executes state transitions via `ledger.prepareUpdate`.
  let id = ?validateBlockAndTransactions(blk, localTree, ledger)

  let prepared = ledger.prepareUpdate(
    id, blk.header.parentBlock, blk.header.slot, blk.header.proofOfLeadership, blk.txs
  ).valueOr:
    if error in {LedgerError.InvalidSlot, LedgerError.InvalidProofOfLeadership, LedgerError.ParentNotFound, LedgerError.UnsupportedLotteryF, LedgerError.VerifierNotInitialised}:
      return err(BlockValidationError(kind: BlockValidationErrorKind.HeaderRejected, ledgerError: error))
    else:
      return err(BlockValidationError(kind: BlockValidationErrorKind.TransactionsRejected, ledgerError: error))

  ok(prepared)

{.pop.}
