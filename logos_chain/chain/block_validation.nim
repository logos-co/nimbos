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
## Spec: [Block Construction, Validation and Execution v1.3.0](https://github.com/logos-co/logos-lips/blob/4deef612ce1ae1776167daf8779d4abae953201b/docs/blockchain/raw/bedrock-v1.1-block-construction.md)

{.push raises: [], gcsafe.}

import
  libp2p/crypto/ed25519/ed25519,
  ../core/local_tree,
  ../core/mantle/tx_validation,
  ../ledger/ledger

export tx_validation.StatelessLedgerError

from ../core/types import
  Block, body_root, ExpectedBedrockVersion,
  MaxBlockSize, MaxUncles, asSeq, len, header, txs, blockId, ValidBlock,
  AdmittedBlock
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

  # Only the commitment to the carried uncle list is checked here; the uncle
  # validity rules (Cryptarchia "Block Header Validation") are not
  # implemented yet.
  let root = body_root(blk.uncleHeaders.asSeq, blk.txs.asSeq).valueOr:
    return false
  if root != h.bodyRoot:
    return false

  if not verify(blk.signature, blockId(h), h.proofOfLeadership.leaderKey):
    return false

  true

func validateBlockStructure(blk: Block): bool =
  if blk.txs.len > MaxBlockTxs:
    return false

  if blk.uncleHeaders.len > MaxUncles:
    return false

  if blk.signature == DefaultEd25519Signature:
    return false

  # The spec bounds uncles by count only; MaxBlockSize covers the transactions.
  if txBytesLen(blk.txs.asSeq) > MaxBlockSize:
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

proc validatePolAndStatelessTransactions*(
    blk: AdmittedBlock,
    ledger: Ledger[BlockId],
    txsToVerify: openArray[SignedMantleTx],
): Result[tuple[validBlk: ValidBlock, headerState: LedgerState], BlockValidationError] =
  ## Tier 3a: Verify PoL against parent state before touching any transactions
  let parentState = ledger.state(blk.header.parentBlock).valueOr:
    return err(BlockValidationError(
      kind: BlockValidationErrorKind.HeaderRejected,
      ledgerError: LedgerError.ParentNotFound,
    ))

  let afterHeader = parentState.tryApplyHeader(
    blk.header.slot,
    blk.header.proofOfLeadership,
    ledger.config,
    ledger.leaderProofVerifier,
  ).valueOr:
    return err(BlockValidationError(
      kind: BlockValidationErrorKind.HeaderRejected,
      ledgerError: error,
    ))

  # Tier 3b: Stateless transaction validation
  ?validateStatelessTransactions(txsToVerify)

  ok((validBlk: ValidBlock(Block(blk)), headerState: afterHeader))

proc validateBlockHeaderAndTopology*(
    blk: Block,
    localTree: LocalTree,
    ledger: Ledger[BlockId],
): Result[tuple[admittedBlk: AdmittedBlock, isOrphan: bool], BlockValidationError] =
  ## Multi-tier block admission and staged header/topology validation:
  ## Tier 0: Structural & size bounds (~1 µs)
  ## Tier 1: Topology & parent existence in localTree/ledger (< 5 µs)
  ## Tier 2a: Body root verification (~20 µs)
  ## Tier 2b: Header Ed25519 signature verification (~0.8 ms)
  ##
  ## Returns ok((admittedBlk, isOrphan: true)) if the block is an orphan (parent state not yet in ledger),
  ## or ok((admittedBlk, isOrphan: false)) if the parent state is present.
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

  ok((admittedBlk: AdmittedBlock(blk), isOrphan: isOrphan))

proc prepareBlockUpdate*(
    blk: ValidBlock,
    ledger: Ledger[BlockId],
    headerState: LedgerState,
): Result[LedgerState, BlockValidationError] =
  ## Executes state transitions via `ledger.prepareUpdate` on a validated block.
  template validTxs: untyped = cast[seq[ValidSignedMantleTx]](blk.txs.asSeq)

  let prepared = ledger.prepareUpdate(
    blk.header.slot, headerState, validTxs
  ).valueOr:
    return err(BlockValidationError(
      kind: BlockValidationErrorKind.TransactionsRejected,
      ledgerError: error,
    ))

  ok(prepared)

{.pop.}
