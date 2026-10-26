# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[algorithm, sequtils],
  results,
  libp2p/crypto/ed25519/ed25519,
  unittest2,
  ../../logos_chain/chain/chain,
  ../../logos_chain/core/mantle/[opcodes, operations, proofs, tx_types],
  ../../logos_chain/zk/poc,
  ./mantle/test_helpers,
  ../testutil
from ../../logos_chain/core/mantle/primitives import MaxBlockTxs, SlotNumber
from ../ledger/test_helpers import testLedgerConfig, testGenesisLedgerState

const
  inscribeOpFraming = 165
    ## Opcode, ChannelId, the u32 inscription length, Parent, Signer and the
    ## 64-byte Ed25519 proof — everything but the inscription itself.
  inscribeTxFraming = 1 + 2 * inscribeOpFraming
    ## OpCount plus two inscribe ops.

func inscribe(size: int, signer: Ed25519PublicKey): Op =
  createChannelInscribeOp(ChannelInscribePayload(
    channelId: default(ChannelId),
    inscription: newSeq[byte](size),
    parent: default(Parent),
    signer: signer,
  ))

proc mkSizedTx(bytes: int): HashedSignedMantleTx =
  ## Two-inscription transaction padded to encode to exactly `bytes`. Two ops
  ## keep each inscription under MaxOperationDataSize at MaxBlockSize.
  doAssert bytes >= inscribeTxFraming
  let
    padding = bytes - inscribeTxFraming
    first = padding div 2
    signer = testTxKeyPair.pubkey
    tx = MantleTx(ops: @[inscribe(first, signer), inscribe(padding - first, signer)])
    txHash = mantleTxHash(tx).get
    proof = OpProof(kind: opfChannelInscribe, ed25519SigProof: sign(testTxKeyPair.seckey, txHash))
  mkHashedSignedTx(SignedMantleTx(tx: tx, opProofs: @[proof, proof]), txHash)

func admitWithTopology(
    blk: Block,
    tree: LocalTree,
    ledger: Ledger[BlockId],
): Result[tuple[admittedBlk: AdmittedBlock, isOrphan: bool], BlockApplyError] =
  let
    status = ?checkTopology(blk.header, tree, ledger)
    admittedBlk = admitBlock(blk).valueOr:
      return err(toBlockApplyError(error))
  ok((admittedBlk: admittedBlk, isOrphan: status == TopologyStatus.Orphan))

proc validate(genesis: ValidBlock, blk: Block): Result[ValidBlock, BlockValidationError] =
  let tree = newLocalTree(genesis, 1'u64)
  let state = testGenesisLedgerState()
  let ledger = Ledger[BlockId].init(
    blockId(genesis.header), state, testLedgerConfig, mockVerifyLeaderProof
  )
  let (admittedBlk, isOrphan) = admitWithTopology(blk, tree, ledger).valueOr:
    case error.kind
    of BlockApplyErrorKind.UnviableFork:
      return err(BlockValidationError(kind: BlockValidationErrorKind.UnviableFork))
    else:
      return err(BlockValidationError(kind: BlockValidationErrorKind.InvalidBlockStructure))
  if isOrphan:
    return err(BlockValidationError(kind: BlockValidationErrorKind.UnviableFork))
  let (validBlk, _) = ?validatePolAndStatelessTransactions(admittedBlk, ledger, nil)
  ok(validBlk)

proc treeWithLib(genesis: ValidBlock): tuple[tree: LocalTree, b1, b2: ValidBlock] =
  ## Tree with security parameter 1 holding genesis, b1, b2, b3; the LIB is b2.
  let
    tree = newLocalTree(genesis, 1'u64)
    b1 = mkChildValidBlock(genesis.header, blockId(genesis.header), SlotNumber(1))
    b2 = mkChildValidBlock(b1.header, blockId(b1.header), SlotNumber(2))
    b3 = mkChildValidBlock(b2.header, blockId(b2.header), SlotNumber(3))
  for blk in [b1, b2, b3]:
    check tree.addBlockToTree(blk)
    tree.tryUpdateLib()
  check tree.latestImmutableBlockId == blockId(b2.header)
  (tree, b1, b2)


func sampleUncle(value: byte): SignedHeader =
  # Arbitrary bytes: only the commitment to an entry is checked, not the entry.
  var
    h: Header
    sig: Ed25519Signature
  h.bedrockVersion = ExpectedBedrockVersion
  h.parentBlock.fill(value)
  h.bodyRoot.fill(value)
  sig.data.fill(value)
  SignedHeader(header: h, signature: sig)

suite "core/block_validation":
  test "accepts a structurally valid block":
    let
      sm = minimalHashedSignedTx()
      genesis = testGenesisBlock()
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    check validate(genesis, b1).isOk

  test "rejects wrong bedrock version":
    let
      sm = minimalHashedSignedTx()
      genesis = testGenesisBlock()
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.header.bedrockVersion = 99'u8
    check validate(genesis, b1).isErr

  test "rejects a body root that disagrees with the transactions":
    let
      sm = minimalHashedSignedTx()
      genesis = testGenesisBlock()
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.header.bodyRoot[0] = b1.header.bodyRoot[0] xor 0xff'u8
    check validate(genesis, b1).isErr

  test "accepts a block whose body root commits to two uncles":
    let
      sm = minimalHashedSignedTx()
      genesis = testGenesisBlock()
      uncles = [sampleUncle(0x11'u8), sampleUncle(0x22'u8)]
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm], uncles)
    check validate(genesis, b1).isOk

  test "rejects a block whose body root ignores its uncles":
    let
      sm = minimalHashedSignedTx()
      genesis = testGenesisBlock()
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.uncleHeaders = UncleHeaders(@[sampleUncle(0x11'u8), sampleUncle(0x22'u8)])
    check validate(genesis, b1).isErr

  test "rejects more than MaxUncles uncles":
    let
      sm = minimalHashedSignedTx()
      genesis = testGenesisBlock()
      uncle = sampleUncle(0x33'u8)
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.uncleHeaders = UncleHeaders(@[uncle, uncle, uncle, uncle, uncle])
    check validate(genesis, b1).isErr

  test "rejects a transaction with mismatched ops and opProofs counts":
    let
      badProof = OpProof(kind: opfTransfer, transferProof: default(ZkSigProof))
      badHtx = mkTransferTx(@[], @[], opProofs = @[badProof, badProof])
      genesis = testGenesisBlock()
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badHtx])
    check validate(genesis, b1).isErr

  test "rejects a transaction with unsupported opcode":
    var badOp = createTransferOp(TransferPayload(inputs: Inputs(noteIds: @[]), outputs: Outputs(notes: @[])))
    badOp.opcode = cast[Opcode](0xff'u8)
    let
      badHtx = mkHashedTx(@[badOp], @[OpProof(kind: opfTransfer, transferProof: default(ZkSigProof))])
      genesis = testGenesisBlock()
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badHtx])
    check validate(genesis, b1).isErr

  test "rejects a transaction with opcode mismatching payload":
    var badOp = createTransferOp(TransferPayload(inputs: Inputs(noteIds: @[]), outputs: Outputs(notes: @[])))
    badOp.opcode = OpChannelInscribe
    let
      badHtx = mkHashedTx(@[badOp], @[OpProof(kind: opfTransfer, transferProof: default(ZkSigProof))])
      genesis = testGenesisBlock()
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badHtx])
    check validate(genesis, b1).isErr

  test "rejects a transaction with proof kind mismatching opcode":
    let
      badProof = OpProof(kind: opfChannelInscribe, ed25519SigProof: default(Ed25519SigProof))
      badHtx = mkTransferTx(@[], @[], opProofs = @[badProof])
      genesis = testGenesisBlock()
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badHtx])
    check validate(genesis, b1).isErr

suite "core/block_validation — inclusive size and count bounds":
  test "a block whose tx bytes are exactly MaxBlockSize is accepted":
    let
      genesis = testGenesisBlock()
      # Only the serialized transactions count; header and block signature don't.
      tx = mkSizedTx(MaxBlockSize)
    check encodeSignedMantleTx(tx).get.len == MaxBlockSize
    let b1 = childBlock(
      genesis.header, blockId(genesis.header), SlotNumber(1), [tx])
    check validate(genesis, b1).isOk

  test "one byte past MaxBlockSize is rejected":
    let
      genesis = testGenesisBlock()
      tx = mkSizedTx(MaxBlockSize + 1)
      b1 = childBlock(
        genesis.header, blockId(genesis.header), SlotNumber(1), [tx])
    check validate(genesis, b1).isErr

  test "a block with exactly MaxBlockTxs transactions is accepted":
    let
      genesis = testGenesisBlock()
      tx = minimalHashedSignedTx()
      txs = newSeqWith(MaxBlockTxs, tx)
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), txs)
    check validate(genesis, b1).isOk

  test "one transaction past MaxBlockTxs is rejected":
    let
      genesis = testGenesisBlock()
      tx = minimalHashedSignedTx()
      txs = newSeqWith(MaxBlockTxs, tx)
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), txs)
      overLong = Block(
        header: b1.header,
        signature: b1.signature,
        txs: BlockTxs(newSeqWith(MaxBlockTxs + 1, tx)),
      )
    check validate(genesis, overLong).isErr

suite "core/block_validation — multi-tier evaluation order":
  test "Tier 2: header signature failure short-circuits with InvalidBlockStructure":
    let
      genesis = testGenesisBlock()
      badTx = SignedMantleTx(
        tx: MantleTx(ops: @[createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[Note(value: 0, zkPublicKey: default(ZkPublicKey))]),
        ))]),
        opProofs: @[OpProof(kind: opfTransfer, transferProof: DefaultZkSignature)],
      )
      badHtx = createHashedSignedMantleTx(badTx).get
    var blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badHtx])
    # Corrupt block header signature
    blk.signature.data[0] = blk.signature.data[0] xor 0xff'u8
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.InvalidBlockStructure

  test "Tier 3: stateless validation rejects malformed non-ZK tx with empty inputs":
    let
      badLightTx = SignedMantleTx(
        tx: MantleTx(ops: @[createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[]),
        ))]),
        opProofs: @[OpProof(kind: opfTransfer, transferProof: DefaultZkSignature)],
      )
      badLightHtx = createHashedSignedMantleTx(badLightTx).get
      validLightTx = minimalHashedSignedTx()
      genesis = testGenesisBlock()
      blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [validLightTx, badLightHtx])
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.StatelessTxRejected
    check res.error.statelessError == StatelessLedgerError.EmptyInputs

  test "Tier 0: rejects block with default zero signature":
    let
      genesis = testGenesisBlock()
      sm = minimalHashedSignedTx()
    var blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    blk.signature = DefaultEd25519Signature
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.InvalidBlockStructure

  test "Tier 1: rejects block with unknown parent":
    let
      genesis = testGenesisBlock()
      sm = minimalHashedSignedTx()
      missingParentId = default(BlockId)
      blk = childBlock(genesis.header, missingParentId, SlotNumber(1), [sm])
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.UnviableFork

  test "Tier 1: rejects block with non-advancing slot (slot <= parent.slot)":
    let
      genesis = testGenesisBlock()
      sm = minimalHashedSignedTx()
      # Genesis is slot 0; a child at slot 0 does not advance
      blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(0), [sm])
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.InvalidBlockStructure

  test "Tier 1: rejects a block extending an ancestor below the LIB":
    let
      genesis = testGenesisBlock()
      (tree, b1, _) = treeWithLib(genesis)
      ledger = Ledger[BlockId].init(
        blockId(genesis.header), default(LedgerState), default(LedgerConfig))
      # b1 is below the LIB with no ledger state, but the tree still holds it.
      sm = minimalHashedSignedTx()
      blk = childBlock(b1.header, blockId(b1.header), SlotNumber(4), [sm])
      res = admitWithTopology(blk, tree, ledger)
    check res.isErr
    check res.error.kind == BlockApplyErrorKind.UnviableFork

  test "Tier 1: unviable fork is rejected with UnviableFork before signature verification":
    let
      genesis = testGenesisBlock()
      (tree, b1, _) = treeWithLib(genesis)
      ledger = Ledger[BlockId].init(
        blockId(genesis.header), default(LedgerState), default(LedgerConfig))
      sm = minimalHashedSignedTx()
      blk = childBlock(b1.header, blockId(b1.header), SlotNumber(4), [sm])
    var corruptBlk = blk
    corruptBlk.signature = testTxKeyPair.seckey.sign(default(Hash32))
    let res = admitWithTopology(corruptBlk, tree, ledger)
    check res.isErr
    check res.error.kind == BlockApplyErrorKind.UnviableFork

  test "Tier 1: accepts a child of the LIB":
    let
      genesis = testGenesisBlock()
      (tree, _, b2) = treeWithLib(genesis)
      sm = minimalHashedSignedTx()
      blk = childBlock(b2.header, blockId(b2.header), SlotNumber(4), [sm])
      state = testGenesisLedgerState()
    var ledger = Ledger[BlockId].init(
      blockId(genesis.header), state, testLedgerConfig, mockVerifyLeaderProof)
    ledger.commitUpdate(blockId(b2.header), state)
    check admitWithTopology(blk, tree, ledger).isOk

  test "Tier 0: rejects block with empty leader key":
    let
      genesis = testGenesisBlock()
      sm = minimalHashedSignedTx()
    var blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    blk.header.proofOfLeadership.leaderKey = DefaultEd25519PublicKey
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.InvalidBlockStructure

  test "Tier 3: rejects transaction with duplicate input noteIds (double spend)":
    let
      note = mkUtxo(value = 100, pkSeed = 1)
      badTx = mkTransferTx(@[note.id, note.id], @[mkNote(100, pkSeed = 2)])
      genesis = testGenesisBlock()
      blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.StatelessTxRejected
    check res.error.statelessError == StatelessLedgerError.DoubleSpend

  test "Tier 3: Pass 2 rejects heavy ZK transaction with invalid proof after light txs pass":
    let
      validLightTx = minimalHashedSignedTx()
      genesis = testGenesisBlock()
      claimTx = SignedMantleTx(
        tx: MantleTx(ops: @[createLeaderClaimOp(LeaderClaimPayload(
          rewardsRoot: default(RewardsRoot),
        ))]),
        opProofs: @[OpProof(kind: opfLeaderClaim, proofOfClaimProof: default(ProofOfClaimProof))],
      )
      claimHtx = createHashedSignedMantleTx(claimTx).get
      blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [validLightTx, claimHtx])
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.StatelessTxRejected
    check res.error.statelessError in {StatelessLedgerError.InvalidProof, StatelessLedgerError.VerifierNotInitialised}

  test "Tier 3: PoL verification failure rejects block before stateless tx validation":
    proc failingPolVerifier(
        proof: ProofOfLeadership, public: LeaderPublic
    ): Result[bool, PolLoadError] =
      ok(false)

    let
      # A transaction that would fail stateless validation (duplicate inputs)
      note = mkUtxo(value = 100, pkSeed = 1)
      badTx = mkTransferTx(@[note.id, note.id], @[mkNote(100, pkSeed = 2)])
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      state = testGenesisLedgerState()
      ledger = Ledger[BlockId].init(gid, state, testLedgerConfig, failingPolVerifier)
      blk = childBlock(genesis.header, gid, SlotNumber(1), [badTx])

    let (admittedBlk, isOrphan) = admitWithTopology(blk, tree, ledger).expect("header valid")
    check not isOrphan
    let res = validatePolAndStatelessTransactions(admittedBlk, ledger, nil)
    check res.isErr
    # PoL failure at Tier 3a triggers HeaderRejected, BEFORE reaching Tier 3b StatelessTxRejected
    check res.error.kind == BlockValidationErrorKind.HeaderRejected
    check res.error.ledgerError == LedgerError.InvalidProofOfLeadership

  test "Tier 3: consensus proof mismatch rejects block even if hash exists in mempool (D1)":
    let
      validLightTx = minimalValidSignedTx()
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      state = testGenesisLedgerState()
      ledger = Ledger[BlockId].init(gid, state, testLedgerConfig, mockVerifyLeaderProof)
    var mempool = Mempool.init()
    check mempool.add(validLightTx, SlotNumber(0))

    # Construct wire tx with same hash as mempool tx, but with corrupted proof
    var tamperedSignedTx = validLightTx.hashed.signedTx
    tamperedSignedTx.opProofs = @[defaultOpProofForOpcode(OpChannelInscribe).get]
    let tamperedHtx = createHashedSignedMantleTx(tamperedSignedTx).get
    # Check mempool rejects fast-path
    check mempool.getKnownValid(tamperedHtx).isNone

    # Construct block with tampered tx
    let
      blk = childBlock(genesis.header, gid, SlotNumber(1), [tamperedHtx])
      (admittedBlk, isOrphan) = admitWithTopology(blk, tree, ledger).expect("header valid")
    check not isOrphan
    let res = validatePolAndStatelessTransactions(admittedBlk, ledger, mempool)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.StatelessTxRejected
    check res.error.statelessError == StatelessLedgerError.InvalidProof

  test "Tier 3: reconstructed proposal bypasses stateless validation via mempool hit (D3)":
    # 1. Construct a LeaderClaim tx with a dummy proof
    let
      op = createLeaderClaimOp(LeaderClaimPayload(
        rewardsRoot: default(RewardsRoot),
        voucherNullifier: default(VoucherNullifier),
        publicKey: mkZkPubKey(1),
      ))
      tx = SignedMantleTx(
        tx: MantleTx(ops: @[op]),
        opProofs: @[OpProof(kind: opfLeaderClaim, proofOfClaimProof: default(ProofOfClaimProof))],
      )
      vtx = mkValidTx(tx)
      htx = vtx.hashed

    var mempool = Mempool.init()
    check mempool.add(vtx, SlotNumber(0))

    # 2. Build block containing this transaction
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      child = childBlock(genesis.header, gid, SlotNumber(1), [htx])

    # 3. Ensure the verifier is uninitialised
    poc.resetVkForTesting()

    # 4. If Tier 3 runs stateless validation, it calls verifyProofOfClaim -> fails with VerifierNotInitialised.
    #    Because it hits the mempool pointer fast-path, it bypasses stateless validation and succeeds!
    let
      tree = newLocalTree(genesis, 1'u64)
      state = testGenesisLedgerState()
      ledger = Ledger[BlockId].init(gid, state, testLedgerConfig, mockVerifyLeaderProof)

    let (admittedBlk, isOrphan) = admitWithTopology(child, tree, ledger).expect("header valid")
    check not isOrphan
    let res = validatePolAndStatelessTransactions(admittedBlk, ledger, mempool)
    check res.isOk

    # 5. Negative check: with empty mempool, Tier 3 falls back to stateless validation and FAILS with VerifierNotInitialised
    let
      emptyMempool = Mempool.init()
      resMiss = validatePolAndStatelessTransactions(admittedBlk, ledger, emptyMempool)
    check resMiss.isErr
    check resMiss.error.kind == BlockValidationErrorKind.StatelessTxRejected
    check resMiss.error.statelessError == StatelessLedgerError.VerifierNotInitialised

  test "prepareBlockUpdate rejects stateful transaction failures":
    let
      sm = minimalHashedSignedTx()
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      blk = childBlock(genesis.header, gid, SlotNumber(1), [sm])
    var state = testGenesisLedgerState()
    # Non-zero base fee causes minimalValidSignedTx with 0 transfer balance to fail fee coverage
    state.feeMarket.executionBaseFee = 1000
    state.feeMarket.storageGasPrice = 1000
    let ledger = Ledger[BlockId].init(gid, state, testLedgerConfig, mockVerifyLeaderProof)
    let (admittedBlk3, isOrphan3) = admitWithTopology(blk, tree, ledger).expect("header valid")
    check not isOrphan3
    let (validBlk, headerState) = validatePolAndStatelessTransactions(admittedBlk3, ledger, nil).expect("header state")
    let res = prepareBlockUpdate(validBlk, ledger, headerState)
    check res.isErr and res.error.kind == BlockValidationErrorKind.TransactionsRejected

  test "Tier 1: admitWithTopology marks isOrphan as true and bypasses PoL/txs for orphan":
    let
      # An orphan with invalid tx that would fail stateless validation if executed
      note = mkUtxo(value = 100, pkSeed = 1)
      badTx = mkTransferTx(@[note.id, note.id], @[mkNote(100, pkSeed = 2)])
      genesis = testGenesisBlock()
      tree = newLocalTree(genesis, 1'u64)
      state = testGenesisLedgerState()
      ledger = Ledger[BlockId].init(blockId(genesis.header), state, testLedgerConfig, mockVerifyLeaderProof)
      orphanParent = Hash32([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
      blk = childBlock(genesis.header, orphanParent, SlotNumber(1), [badTx])

    # Ingestion skips Tier 3 PoL & tx checks for orphans
    let res = admitWithTopology(blk, tree, ledger)
    check res.isOk
    check res.get.isOrphan == true

  test "validatePolAndStatelessTransactions consumes validTxs from proposal-admitted block":
    let
      validTx = minimalValidSignedTx()
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      proposal = childProposal(genesis.header, gid, SlotNumber(1), [validTx])
      admitted = admitProposal(proposal, @[validTx]).expect("valid proposal")

    check admitted.validTxs.len == 1
    let
      state = testGenesisLedgerState()
      ledger = Ledger[BlockId].init(gid, state, testLedgerConfig, mockVerifyLeaderProof)

    let res = validatePolAndStatelessTransactions(admitted, ledger, nil)
    check res.isOk
    let (validBlk, _) = res.get()
    check validBlk.txs.len == 1
    doAssert admitted.validTxs.len == 0,
      "admitted block validTxs must be consumed by validatePolAndStatelessTransactions"

  test "bodyMatchesHeader unit tests for Proposal and Block":
    let
      validTx = minimalValidSignedTx()
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      proposal = childProposal(genesis.header, gid, SlotNumber(1), [validTx])
      blk = childBlock(genesis.header, gid, SlotNumber(1), [validTx.hashed])

    # Genuine proposal & block match
    check proposal.bodyMatchesHeader == true
    check blk.bodyMatchesHeader == true

    # Proposal with modified reference fails
    var badRefProp = proposal
    badRefProp.references[0][0] = badRefProp.references[0][0] xor 0xff'u8
    check badRefProp.bodyMatchesHeader == false

    # Proposal with dropped reference (early zero) fails
    var droppedRefProp = proposal
    droppedRefProp.references[0] = default(Hash32)
    check droppedRefProp.bodyMatchesHeader == false

    # Proposal with modified uncle fails
    var badUncleProp = proposal
    badUncleProp.uncleHeaders = UncleHeaders(@[sampleUncle(0x11'u8)])
    check badUncleProp.bodyMatchesHeader == false

    # Block with modified transaction hash fails
    var badTxBlk = blk
    var alteredHash = validTx.hash
    alteredHash[0] = alteredHash[0] xor 0xff'u8
    let badTx = mkHashedSignedTx(validTx.hashed.signedTx, alteredHash)
    badTxBlk.txs = BlockTxs(@[badTx])
    check badTxBlk.bodyMatchesHeader == false

    # Block with modified uncle fails
    var badUncleBlk = blk
    badUncleBlk.uncleHeaders = UncleHeaders(@[sampleUncle(0x11'u8)])
    check badUncleBlk.bodyMatchesHeader == false

{.pop.}
