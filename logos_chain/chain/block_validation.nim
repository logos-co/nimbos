# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Stateless structural checks of Bedrock `valid_header(B)`. The stateful
## half (parent linkage, slot ordering, wallclock bound, leader proof verification
## called during `tryApplyHeader` in `ledger.nim`) is owned by the `Chain.tryApplyBlock`
## composition: ledger `prepareUpdate` plus `LocalTree.addBlockToTree`.
## Spec: [1.1.1 Block Construction, Validation and Execution](https://nomos-tech.notion.site/1-1-1-Block-Construction-Validation-and-Execution-269261aa09df807185a9e0764acffe22)

{.push raises: [], gcsafe.}

import
  results,
  ../core/local_tree,
  ../ledger/ledger,
  libp2p/crypto/ed25519/ed25519

from ../core/types import
  Block, createBlockRoot, ExpectedBedrockVersion, MaxBlockSize, header, blockId
from ../core/mantle/primitives import MaxBlockTxs
from ../core/mantle/tx_types import
  SignedMantleTx,
  encodeSignedMantleTx,
  isSupportedOpcode,
  opPayloadToOpcode,
  expectedOpProofKindForOpcode

func txBytesLen(txs: openArray[SignedMantleTx]): int =
  var total = 0
  for stx in txs:
    total += encodeSignedMantleTx(stx).len
  total

func blockPayloadBytesLen(blk: Block): int =
  ## Mantle tx bytes plus the 64-byte Ed25519 block signature.
  ## IBD additionally caps the full bincode wire blob (header framing + signature + txs).
  txBytesLen(blk.txs) + EdSignatureSize

func validateBlockHeader(blk: Block): bool =
  if header(blk).bedrockVersion != ExpectedBedrockVersion:
    return false

  if createBlockRoot(blk.txs) != header(blk).blockRoot:
    return false

  if not verify(blk.signature, blockId(header(blk)), header(blk).proofOfLeadership.leaderKey):
    return false

  true

func validateBlockBody(blk: Block): bool =
  if blockPayloadBytesLen(blk) >= MaxBlockSize:
    return false

  if blk.txs.len >= MaxBlockTxs:
    return false

  for tx in blk.txs:
    if tx.tx.ops.len != tx.opProofs.len:
      return false
    for i in 0 ..< tx.tx.ops.len:
      let op = tx.tx.ops[i]
      if not isSupportedOpcode(op.opcode):
        return false
      if op.opcode != opPayloadToOpcode(op.payload):
        return false
      if tx.opProofs[i].kind != expectedOpProofKindForOpcode(op.opcode):
        return false
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
