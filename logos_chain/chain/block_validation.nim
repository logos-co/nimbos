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
  libp2p/crypto/ed25519/ed25519,
  ../core/local_tree,
  ../core/mantle/tx_validation,
  ../ledger/ledger

export tx_validation.StatelessLedgerError

from ../core/types import
  Block, Header, Proposal, References, createBlockRoot, ExpectedBedrockVersion,
  MaxBlockSize, header, txs, blockId, Hash32, ValidBlock
from ../core/mantle/primitives import MaxBlockTxs, SlotNumber
from ../core/mantle/tx_types import SignedMantleTx, ValidSignedMantleTx, byteLen

type
  BlockValidationErrorKind* {.pure.} = enum
    InvalidBlockStructure
    UnviableFork       # parent known; at or behind the immutable ancestor
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
  for i in 0 ..< txs.len:
    total += byteLen(txs[i])
  total

func validateBlockHeader(blk: Block): bool =
  let h = header(blk)
  if h.bedrockVersion != ExpectedBedrockVersion:
    return false

  if h.proofOfLeadership.leaderKey == DefaultEd25519PublicKey:
    return false

  if h.slot > 0 and h.parentBlock.isZero:
    return false

  if blk.txs.len > 0 and h.blockRoot.isZero:
    return false

  let root = createBlockRoot(blk.txs).valueOr:
    return false
  if root != h.blockRoot:
    return false

  if not verify(blk.signature, blockId(h), h.proofOfLeadership.leaderKey):
    return false

  true

func validateBlockStructure(blk: Block): bool =
  if blk.txs.len > MaxBlockTxs:
    return false

  if blk.signature == DefaultEd25519Signature:
    return false

  if txBytesLen(blk.txs) > MaxBlockSize:
    return false

  true

proc validateStatelessTransactions(
    txs: openArray[SignedMantleTx],
): Result[void, BlockValidationError] =
  ## Validates mantle transactions statelessly using a 2-pass light-first scan:
  ## Pass 1: Light (non-ZK) transactions (~130 ns per tx)
  ## Pass 2: Heavy ZK transactions (LeaderClaim Groth16 proofs, ~1.13 ms per tx)
  if txs.len == 0:
    return ok()

  template validateTx(tx: SignedMantleTx): untyped =
    validateMantleTxStateless(tx).isOkOr:
      return err(BlockValidationError(
        kind: BlockValidationErrorKind.StatelessTxRejected,
        statelessError: error,
      ))

  var heavyIndices: seq[int]

  # Pass 1: Validate light txs, record heavy ZK txs without running heavy verifications
  for i in 0 ..< txs.len:
    if txs[i].hasHeavyZkProof():
      heavyIndices.add(i)
    else:
      validateTx(txs[i])

  # Pass 2: Validate heavy ZK txs (only if any exist)
  for idx in heavyIndices:
    validateTx(txs[idx])

  ok()

proc validateBlock*(
    blk: Block,
    localTree: LocalTree,
    ledger: Ledger[BlockId],
    txsToVerify: openArray[SignedMantleTx],
): Result[tuple[blk: ValidBlock, isOrphan: bool], BlockValidationError] =
  ## Multi-tier block admission and stateless transaction validation:
  ## Tier 0: Structural & size bounds (~1 µs)
  ## Tier 1: Topology & parent existence in localTree/ledger (< 5 µs)
  ## Tier 2: Merkle root & Ed25519 signature verification (~1.9 ms)
  ## Tier 3: Light-first stateless transaction validation on `txsToVerify` (0 - 5.2s).
  ## Only `txsToVerify` will be validated; if empty, all transactions are in the mempool
  ## thus no need to validate statelessly.
  ##
  ## If the block's parent is missing from the ledger, it is treated as an orphan.
  ## Validation does not terminate early; Tier 2 (header signature/root) and Tier 3
  ## (stateless transactions) are executed to ensure malformed blocks are rejected
  ## before buffering. If all checks pass, `isOrphan` is true.
  if not validateBlockStructure(blk):
    return err(BlockValidationError(kind: BlockValidationErrorKind.InvalidBlockStructure))

  let isOrphan = not ledger.hasState(blk.header.parentBlock)
  if not isOrphan:
    let parentHdr = localTree.fetchHeader(blk.header.parentBlock).valueOr:
      return err(BlockValidationError(kind: BlockValidationErrorKind.UnviableFork))
    if blk.header.slot <= parentHdr.slot:
      return err(BlockValidationError(kind: BlockValidationErrorKind.InvalidBlockStructure))

  if not localTree.canDescendFromImmutable(blk.header):
    return err(BlockValidationError(kind: BlockValidationErrorKind.UnviableFork))

  if not validateBlockHeader(blk):
    return err(BlockValidationError(kind: BlockValidationErrorKind.InvalidBlockStructure))

  ?validateStatelessTransactions(txsToVerify)

  ok((blk: ValidBlock(blk), isOrphan: isOrphan))

proc prepareBlockUpdate*(
    blk: ValidBlock,
    ledger: Ledger[BlockId],
): Result[tuple[id: BlockId, state: LedgerState], BlockValidationError] =
  ## Executes state transitions via `ledger.prepareUpdate` on a validated block.
  let id = blockId(blk.header)
  template validTxs: untyped = cast[seq[ValidSignedMantleTx]](blk.txs)

  let prepared = ledger.prepareUpdate(
    id,
    blk.header.parentBlock,
    blk.header.slot,
    blk.header.proofOfLeadership,
    validTxs,
  ).valueOr:
    if error in {LedgerError.InvalidSlot, LedgerError.InvalidProofOfLeadership, LedgerError.ParentNotFound, LedgerError.UnsupportedLotteryF, LedgerError.VerifierNotInitialised}:
      return err(BlockValidationError(kind: BlockValidationErrorKind.HeaderRejected, ledgerError: error))
    else:
      return err(BlockValidationError(kind: BlockValidationErrorKind.TransactionsRejected, ledgerError: error))

  ok(prepared)

{.pop.}
