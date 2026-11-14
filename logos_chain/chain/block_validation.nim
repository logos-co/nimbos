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
  std/sequtils,
  bincode,
  libp2p/crypto/ed25519/ed25519,
  ../ledger/ledger,
  ../mempool
from ../core/mantle/tx_validation import
  StatelessLedgerError, ValidSignedMantleTx, ValidGenesisMantleTx,
  hasHeavyZkProof, validateMantleTxStateless, hashed, byteLen,
  AnyHashedSignedMantleTx
export StatelessLedgerError

from ../core/types import
  Block, BlockTxs, Proposal, body_root, ExpectedBedrockVersion,
  MaxBlockSize, MaxUncles, asSeq, len, header, BlockId,
  Header, UncleHeaders, encode, MaxBlockTxs,
  createGenesisHeader, verify_signature
from ../core/crypto/types import isSmallOrder
from ../core/mantle/tx_hashing import
  HashedSignedMantleTx, byteLen, signedTx

type
  AdmittedBlock* = ref object
    ## A block that has successfully passed structural, body root,
    ## and header signature verifications (Tiers 0–2).
    ## Can only be produced via ``admitBlock`` (unverified txs)
    ## or ``admitProposal`` (pre-verified txs).
    header: Header
    signature: Ed25519Signature
    uncleHeaders: UncleHeaders
    case txsVerified: bool
    of false:
      txs: BlockTxs
    of true:
      validTxs: seq[ValidSignedMantleTx]

  ValidBlock* = ref object
    ## In-memory block structure holding verified header and transaction pointers.
    ## A block that has successfully passed all structural, admission,
    ## and stateless transaction verifications via ``validateStatelessTransactions``,
    ## or is constructed via ``createGenesisBlock``.
    header: Header
    signature: Ed25519Signature
    uncleHeaders: UncleHeaders
    txs: seq[ValidSignedMantleTx]

  ProposalValidationError* {.pure.} = enum
    InvalidHeader        ## a header rule that needs no chain state
    InvalidSignature
    UnresolvedReference  ## no unique local transaction for a reference
    BodyRootMismatch
    InvalidStructure     ## a count or byte bound over the resolved body

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

template header*(b: AdmittedBlock): Header = b.header
template signature*(b: AdmittedBlock): Ed25519Signature = b.signature
template uncleHeaders*(b: AdmittedBlock): UncleHeaders = b.uncleHeaders

template header*(blk: ValidBlock): Header = blk.header
template signature*(blk: ValidBlock): Ed25519Signature = blk.signature
template txs*(blk: ValidBlock): seq[ValidSignedMantleTx] = blk.txs

func txBytesLen[T: AnyHashedSignedMantleTx](txs: openArray[T]): int =
  var total = 0
  for i in 0 ..< txs.len:
    total += byteLen(txs[i])
  total

func bodyMatchesHeader*(blk: Block): bool =
  body_root(blk.uncleHeaders.asSeq, blk.txs.asSeq) == blk.header.bodyRoot

func headerRulesHold(header: Header): bool =
  if header.bedrockVersion != ExpectedBedrockVersion:
    return false

  # Stands in for strict verification (Common Cryptographic Components 1.2.0,
  # EdDSA: reject a small-order A), which `verify_signature` does not do yet.
  # Anyone can sign under a small-order key. The all-zero key is also the
  # leader key of the genesis proof, which the PoL verifier accepts at any
  # slot. Delete this check when every signature uses strict verification.
  if header.proofOfLeadership.leaderKey.isSmallOrder:
    return false

  # Stateless proxy of the "parent is in the block tree" rule.
  if header.slot > 0 and header.parentBlock.isZero:
    return false

  true

func validateHeader[T: AnyHashedSignedMantleTx](
    header: Header,
    signature: Ed25519Signature,
    uncleHeaders: UncleHeaders,
    txs: openArray[T],
): bool =
  if not headerRulesHold(header):
    return false

  # Only the commitment to the carried uncle list is checked here. The uncle
  # validity rules (Cryptarchia "Block Header Validation" step 10) live in
  # `uncle_validation.nim` and run against the parent chain.
  # `addBlock` checks `bodyMatchesHeader` before it queues a synced block, and
  # it is the only route into `tryApplyBlock`, so this body-root check repeats
  # that one. The signature check is not a repeat: a synced block gets it only
  # here. TODO: let `addBlock` produce the `AdmittedBlock`, as the gossip gate
  # does with `admitProposal`, and drop the repeat.
  let root = body_root(uncleHeaders.asSeq, txs)
  if root != header.bodyRoot:
    return false

  if not verify_signature(header, signature):
    return false

  true

func validateBlockStructure[T: AnyHashedSignedMantleTx](
    signature: Ed25519Signature,
    uncleHeaders: UncleHeaders,
    txs: openArray[T],
): bool =
  if txs.len > MaxBlockTxs:
    return false

  if uncleHeaders.len > MaxUncles:
    return false

  if signature == DefaultEd25519Signature:
    return false

  # The spec bounds uncles by count only; MaxBlockSize covers the transactions.
  if txBytesLen(txs) > MaxBlockSize:
    return false

  true

func validateStatelessBlock[T: AnyHashedSignedMantleTx](
    header: Header,
    signature: Ed25519Signature,
    uncleHeaders: UncleHeaders,
    txs: openArray[T],
): bool =
  validateBlockStructure(signature, uncleHeaders, txs) and
    validateHeader(header, signature, uncleHeaders, txs)

func admitBlock*(
    blk: Block,
): Result[AdmittedBlock, BlockValidationError] =
  ## Multi-tier stateless block admission:
  ## Tier 0: Structural & size bounds (~1 µs)
  ## Tier 2a: Body root verification (~20 µs)
  ## Tier 2b: Header Ed25519 signature verification (~0.8 ms)
  ##
  ## On successful validation, transitions Block into AdmittedBlock.
  if not validateStatelessBlock(blk.header, blk.signature, blk.uncleHeaders, blk.txs.asSeq):
    return err(BlockValidationError(kind: BlockValidationErrorKind.InvalidBlockStructure))

  ok(AdmittedBlock(
    header: blk.header,
    signature: blk.signature,
    uncleHeaders: blk.uncleHeaders,
    txsVerified: false,
    txs: blk.txs,
  ))

func admitProposal*(
    proposal: Proposal,
    mempool: Mempool,
): Result[AdmittedBlock, ProposalValidationError] =
  ## Runs every proposal check that needs no chain state, with the
  ## transactions that the references resolve to in `mempool`.
  # Header bytes and the signature are checked before any mempool access.
  if not headerRulesHold(proposal.header):
    return err(ProposalValidationError.InvalidHeader)

  if not verify_signature(proposal.header, proposal.signature):
    return err(ProposalValidationError.InvalidSignature)

  var validTxs = newSeqOfCap[ValidSignedMantleTx](proposal.references.len)
  for reference in proposal.references.asSeq:
    let vtx = mempool.resolve(reference).valueOr:
      return err(ProposalValidationError.UnresolvedReference)
    validTxs.add(vtx)

  # Only the body root binds the unsigned reference list to the signed header.
  if body_root(proposal.uncleHeaders.asSeq, validTxs) != proposal.header.bodyRoot:
    return err(ProposalValidationError.BodyRootMismatch)

  if not validateBlockStructure(proposal.signature, proposal.uncleHeaders, validTxs):
    return err(ProposalValidationError.InvalidStructure)

  ok(AdmittedBlock(
    header: proposal.header,
    signature: proposal.signature,
    uncleHeaders: proposal.uncleHeaders,
    txsVerified: true,
    validTxs: move(validTxs),
  ))

proc validatePol*(
    blk: AdmittedBlock,
    ledger: Ledger[BlockId],
): Result[LedgerState, BlockValidationError] =
  ## Tier 3a: verifies the PoL of `blk` against its parent state and returns
  ## the state after the header.
  let parentState = ledger.state(blk.header.parentBlock).valueOr:
    return err(BlockValidationError(
      kind: BlockValidationErrorKind.HeaderRejected,
      ledgerError: LedgerError.ParentNotFound,
    ))

  var afterHeader = parentState.tryApplyHeader(
    blk.header.slot,
    blk.header.proofOfLeadership,
    blk.uncleHeaders.asSeq.mapIt(it.header.slot),
    ledger.config,
    ledger.leaderProofVerifier,
  ).valueOr:
    return err(BlockValidationError(
      kind: BlockValidationErrorKind.HeaderRejected,
      ledgerError: error,
    ))
  ok(move(afterHeader))

proc validateStatelessTransactions*(
    blk: AdmittedBlock,
    mempool: Mempool,
): Result[ValidBlock, BlockValidationError] =
  ## Tier 3b: stateless checks of the transactions of `blk`, light before heavy
  ## ZK.
  # Light (non-ZK) txs cost ~130 ns, heavy ZK txs (LeaderClaim Groth16 proofs)
  # ~1.13 ms. Txs already verified in the mempool skip the crypto checks.
  template validBlock(validTxs: untyped): untyped =
    ValidBlock(
      header: blk.header,
      signature: blk.signature,
      uncleHeaders: blk.uncleHeaders,
      txs: validTxs,
    )

  template validateTx(htx: HashedSignedMantleTx): untyped =
    validateMantleTxStateless(htx).valueOr:
      return err(BlockValidationError(
        kind: BlockValidationErrorKind.StatelessTxRejected,
        statelessError: error,
      ))

  # Copy, not move: `blk` keeps its transactions, so a second apply of the
  # same block cannot apply an empty body under a header that commits to txs.
  if blk.txsVerified:
    return ok(validBlock(blk.validTxs))

  template txs: untyped = blk.txs.asSeq
  var
    heavyIndices: seq[int]
    res = newSeq[ValidSignedMantleTx](txs.len)

  # Pass 1: Validate unverified light txs, record heavy ZK txs without running heavy verifications
  for i in 0 ..< txs.len:
    let
      htx = txs[i]
      known = mempool.getKnownValid(htx).valueOr:
        if htx.signedTx.hasHeavyZkProof():
          heavyIndices.add(i)
        else:
          res[i] = validateTx(htx)
        continue
    res[i] = known

  # Pass 2: Validate unverified heavy ZK txs (only if any exist)
  for i in heavyIndices:
    res[i] = validateTx(txs[i])

  ok(validBlock(move(res)))

proc prepareBlockUpdate*(
    blk: ValidBlock,
    ledger: Ledger[BlockId],
    headerState: LedgerState,
): Result[LedgerState, BlockValidationError] =
  ## Executes state transitions via `ledger.prepareUpdate` on a validated block.
  var prepared = ledger.prepareUpdate(
    blk.header.slot, headerState, blk.txs
  ).valueOr:
    return err(BlockValidationError(
      kind: BlockValidationErrorKind.TransactionsRejected,
      ledgerError: error,
    ))

  ok(move(prepared))

func createGenesisBlock*(validGenesisTx: ValidGenesisMantleTx): ValidBlock =
  ## GENESIS_BLOCK = (GENESIS_HEADER, [GENESIS_MANTLE_TX]); the zero signature
  ## and the empty uncle list are implementation-defined, the spec sets neither.
  ValidBlock(
    header: createGenesisHeader(validGenesisTx),
    signature: DefaultEd25519Signature,
    uncleHeaders: default(UncleHeaders),
    txs: @[ValidSignedMantleTx(validGenesisTx)],
  )

# Custom ValidBlock codec:
# 1. Wire compatibility: `ValidBlock` contains `seq[ValidSignedMantleTx]`, which hold
#    precomputed transaction hashes in memory. Encoding emits only `vtx.signedTx`, producing
#    identical wire bytes to `Block`.
# 2. Typestate safety: `ValidBlock` is strictly an outgoing/verified representation and
#    must not provide a deserializer (`decode`), ensuring untrusted wire bytes always decode
#    into `Block` and pass full validation before becoming `ValidBlock`.
proc encode*(
    stream: OutputStreamHandle,
    blk: ValidBlock,
    config: BincodeConfig,
) {.raises: [BincodeError, IOError].} =
  encode(stream, blk.header, config)
  encode(stream, blk.signature, config)
  encode(stream, blk.uncleHeaders, config)
  encodeLength(stream, blk.txs.len.uint64, config)
  for vtx in blk.txs:
    encode(stream, vtx.hashed, config)

when defined(unittest) or defined(test):
  template validTxs*(b: AdmittedBlock): seq[ValidSignedMantleTx] = b.validTxs

  func createAdmittedBlockForTest*(blk: Block): AdmittedBlock {.inline.} =
    AdmittedBlock(
      header: blk.header,
      signature: blk.signature,
      uncleHeaders: blk.uncleHeaders,
      txsVerified: false,
      txs: blk.txs,
    )

  func createValidBlockForTest*(
      header: Header,
      signature: Ed25519Signature,
      uncleHeaders: UncleHeaders,
      txs: openArray[ValidSignedMantleTx],
  ): ValidBlock =
    ValidBlock(
      header: header,
      signature: signature,
      uncleHeaders: uncleHeaders,
      txs: @txs,
    )

{.pop.}
