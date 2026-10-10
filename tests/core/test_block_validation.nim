# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/algorithm,
  bearssl/rand,
  libp2p/crypto/ed25519/ed25519,
  ../../logos_chain/chain/[block_validation, genesis, proposal],
  ../../logos_chain/core/local_tree,
  ../../logos_chain/ledger/ledger,
  ../../logos_chain/mempool,
  ./mantle/test_helpers,
  ../testutil
from ../ledger/sdp/test_helpers import testSdpRegistry
from ../ledger/test_helpers import testLedgerConfig

const inscribeTxFraming = 166
  ## OpCount, Opcode, ChannelId, the u32 inscription length, Parent, Signer
  ## and the 64-byte Ed25519 proof — everything but the inscription itself.

proc mkSizedTx(bytes: int): SignedMantleTx =
  ## ChannelInscribe transaction padded to encode to exactly `bytes`.
  doAssert bytes >= inscribeTxFraming
  let
    rng = HmacDrbgContext.new()
    kp = mkEdKeyPair(rng)
    tx = MantleTx(ops: @[createChannelInscribeOp(ChannelInscribePayload(
      channelId: default(ChannelId),
      inscription: newSeq[byte](bytes - inscribeTxFraming),
      parent: default(Parent),
      signer: kp.pubkey,
    ))])
    txHash = mantleTxHash(tx).get
    sig = sign(kp.seckey, txHash)
  SignedMantleTx(
    tx: tx,
    opProofs: @[OpProof(kind: opfChannelInscribe, ed25519SigProof: sig)],
  )

proc validate(genesis: Block, blk: Block): Result[ValidBlock, BlockValidationError] =
  let
    tree = newLocalTree(genesis, 1'u64)
    state = LedgerState.fromGenesis(
      testGenesisTx(), default(FieldElement), testSdpRegistry(), testLedgerConfig
    ).valueOr:
      raiseAssert "validate helper init: " & $error
    ledger = Ledger[BlockId].init(
      blockId(genesis.header), state, testLedgerConfig, mockVerifyLeaderProof
    )
    (admittedBlk, isOrphan) = ?validateBlockHeaderAndTopology(blk, tree, ledger)
  if isOrphan:
    return err(BlockValidationError(kind: BlockValidationErrorKind.UnviableFork))
  let (validBlk, _) = ?validatePolAndStatelessTransactions(admittedBlk, ledger, blk.txs.asSeq)
  ok(validBlk)

proc treeWithLib(genesis: Block): tuple[tree: LocalTree, b1, b2: Block] =
  ## Tree with security parameter 1 holding genesis, b1, b2, b3; the LIB is b2.
  let
    sm = minimalSignedTx()
    tree = newLocalTree(genesis, 1'u64)
    b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b2 = childBlock(b1.header, blockId(b1.header), SlotNumber(2), [sm])
    b3 = childBlock(b2.header, blockId(b2.header), SlotNumber(3), [sm])
  for blk in [b1, b2, b3]:
    check tree.addBlockToTree(blk)
    tree.tryUpdateLib()
  check tree.latestImmutableBlockId == blockId(b2.header)
  (tree, b1, b2)

proc childProposal(
    parentHdr: Header,
    parentId: BlockId,
    slot: SlotNumber,
    txs: openArray[SignedMantleTx],
): Proposal =
  var proofOfLeadership = parentHdr.proofOfLeadership
  proofOfLeadership.leaderKey = testBlockKeyPair.pubkey

  let
    h = initHeader(
      bedrockVersion = parentHdr.bedrockVersion,
      parentBlock = parentId,
      slot = slot,
      uncleHeaders = [],
      txs = txs,
      proofOfLeadership = proofOfLeadership,
    ).get
    sig = testBlockKeyPair.seckey.sign(blockId(h))
  var refs: References
  for i, tx in txs:
    refs[i] = mantleTxHash(tx.tx).get
  initProposal(h, [], refs, sig)

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
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm).get
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    check validate(genesis, b1).isOk

  test "rejects wrong bedrock version":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm).get
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.header.bedrockVersion = 99'u8
    check validate(genesis, b1).isErr

  test "rejects a body root that disagrees with the transactions":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm).get
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.header.bodyRoot[0] = b1.header.bodyRoot[0] xor 0xff'u8
    check validate(genesis, b1).isErr

  test "accepts a block whose body root commits to two uncles":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm).get
      uncles = [sampleUncle(0x11'u8), sampleUncle(0x22'u8)]
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm], uncles)
    check validate(genesis, b1).isOk

  test "rejects a block whose body root ignores its uncles":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm).get
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.uncleHeaders = UncleHeaders(@[sampleUncle(0x11'u8), sampleUncle(0x22'u8)])
    check validate(genesis, b1).isErr

  test "rejects more than MaxUncles uncles":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm).get
      uncle = sampleUncle(0x33'u8)
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.uncleHeaders = UncleHeaders(@[uncle, uncle, uncle, uncle, uncle])
    check validate(genesis, b1).isErr

  test "rejects a transaction with mismatched ops and opProofs counts":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm).get
    var badTx = sm
    badTx.opProofs.add(badTx.opProofs[0]) # 1 op, 2 proofs
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    check validate(genesis, b1).isErr

  test "rejects a transaction with unsupported opcode":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm).get
    var badTx = sm
    badTx.tx.ops[0].opcode = cast[Opcode](0xff'u8)
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    check validate(genesis, b1).isErr

  test "rejects a transaction with opcode mismatching payload":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm).get
    var badTx = sm
    badTx.tx.ops[0].opcode = OpChannelInscribe
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    check validate(genesis, b1).isErr

  test "rejects a transaction with proof kind mismatching opcode":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm).get
    var badTx = sm
    badTx.opProofs[0] = OpProof(kind: opfChannelInscribe,
        ed25519SigProof: default(Ed25519SigProof))
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    check validate(genesis, b1).isErr

suite "core/block_validation — inclusive size and count bounds":
  test "a block whose tx bytes are exactly MaxBlockSize is accepted":
    let
      genesis = createGenesisBlock(minimalSignedTx()).get
      # Only the serialized transactions count; header and block signature don't.
      tx = mkSizedTx(MaxBlockSize)
    check encodeSignedMantleTx(tx).get.len == MaxBlockSize
    let b1 = childBlock(
      genesis.header, blockId(genesis.header), SlotNumber(1), [tx])
    check validate(genesis, b1).isOk

  test "one byte past MaxBlockSize is rejected":
    let
      genesis = createGenesisBlock(minimalSignedTx()).get
      tx = mkSizedTx(MaxBlockSize + 1)
      b1 = childBlock(
        genesis.header, blockId(genesis.header), SlotNumber(1), [tx])
    check validate(genesis, b1).isErr

  test "a block with exactly MaxBlockTxs transactions is accepted":
    let
      genesis = createGenesisBlock(minimalSignedTx()).get
      txs = newSeq[SignedMantleTx](MaxBlockTxs)
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), txs)
    check validate(genesis, b1).isOk

  test "one transaction past MaxBlockTxs is rejected":
    let
      genesis = createGenesisBlock(minimalSignedTx()).get
      txs = newSeq[SignedMantleTx](MaxBlockTxs)
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), txs)
      overLong = Block(
        header: b1.header,
        signature: b1.signature,
        txs: BlockTxs(newSeq[SignedMantleTx](MaxBlockTxs + 1)),
      )
    check validate(genesis, overLong).isErr

suite "core/block_validation — multi-tier evaluation order":
  test "header signature failure short-circuits with InvalidBlockStructure":
    let
      genesis = createGenesisBlock(minimalSignedTx()).get
      badTx = SignedMantleTx(
        tx: MantleTx(ops: @[createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[Note(value: 0, zkPublicKey: default(ZkPublicKey))]),
        ))]),
        opProofs: @[OpProof(kind: opfTransfer, transferProof: DefaultZkSignature)],
      )
    var blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    # Corrupt block header signature
    blk.signature.data[0] = blk.signature.data[0] xor 0xff'u8
    let res = validate(genesis, blk)
    check:
      res.isErr
      res.error.kind == BlockValidationErrorKind.InvalidBlockStructure

  test "light-first scanning rejects malformed non-ZK tx before ZK txs":
    let
      badLightTx = SignedMantleTx(
        tx: MantleTx(ops: @[createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[]),
        ))]),
        opProofs: @[OpProof(kind: opfTransfer, transferProof: DefaultZkSignature)],
      )
      validLightTx = minimalSignedTx()
      genesis = createGenesisBlock(validLightTx).get
      blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [validLightTx, badLightTx])
      res = validate(genesis, blk)
    check:
      res.isErr
      res.error.kind == BlockValidationErrorKind.StatelessTxRejected
      res.error.statelessError == StatelessLedgerError.EmptyInputs

  test "Tier 0: rejects block with default zero signature":
    let
      genesis = createGenesisBlock(minimalSignedTx()).get
      sm = minimalSignedTx()
    var blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    blk.signature = DefaultEd25519Signature
    let res = validate(genesis, blk)
    check:
      res.isErr
      res.error.kind == BlockValidationErrorKind.InvalidBlockStructure

  test "Tier 1: rejects block with unknown parent":
    let
      genesis = createGenesisBlock(minimalSignedTx()).get
      sm = minimalSignedTx()
      missingParentId = default(BlockId)
      blk = childBlock(genesis.header, missingParentId, SlotNumber(1), [sm])
      res = validate(genesis, blk)
    check:
      res.isErr
      res.error.kind == BlockValidationErrorKind.UnviableFork

  test "Tier 1: rejects block with non-advancing slot (slot <= parent.slot)":
    let
      genesis = createGenesisBlock(minimalSignedTx()).get
      sm = minimalSignedTx()
      # Genesis is slot 0; a child at slot 0 does not advance
      blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(0), [sm])
      res = validate(genesis, blk)
    check:
      res.isErr
      res.error.kind == BlockValidationErrorKind.InvalidBlockStructure

  test "Tier 1: rejects a block extending an ancestor below the LIB":
    let
      genesis = createGenesisBlock(minimalSignedTx()).get
      (tree, b1, _) = treeWithLib(genesis)
      ledger = Ledger[BlockId].init(
        blockId(genesis.header), default(LedgerState), default(LedgerConfig))
      # b1 is below the LIB with no ledger state, but the tree still holds it.
      blk = childBlock(b1.header, blockId(b1.header), SlotNumber(4), [minimalSignedTx()])
      res = validateBlockHeaderAndTopology(blk, tree, ledger)
    check:
      res.isErr
      res.error.kind == BlockValidationErrorKind.UnviableFork

  test "Tier 1: accepts a child of the LIB":
    let
      genesis = createGenesisBlock(minimalSignedTx()).get
      (tree, _, b2) = treeWithLib(genesis)
      blk = childBlock(b2.header, blockId(b2.header), SlotNumber(4), [minimalSignedTx()])
      state = LedgerState.fromGenesis(
        testGenesisTx(), default(FieldElement), testSdpRegistry(), testLedgerConfig
      ).expect("genesis state")
    var ledger = Ledger[BlockId].init(
      blockId(genesis.header), state, testLedgerConfig, mockVerifyLeaderProof)
    ledger.commitUpdate(blockId(b2.header), state)
    check validateBlockHeaderAndTopology(blk, tree, ledger).isOk

  test "Tier 2: rejects block with empty leader key":
    let
      genesis = createGenesisBlock(minimalSignedTx()).get
      sm = minimalSignedTx()
    var blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    blk.header.proofOfLeadership.leaderKey = DefaultEd25519PublicKey
    let res = validate(genesis, blk)
    check:
      res.isErr
      res.error.kind == BlockValidationErrorKind.InvalidBlockStructure

  test "Tier 3: rejects transaction with duplicate input noteIds (double spend)":
    let
      note = mkUtxo(value = 100, pkSeed = 1)
      badTx = mkTransferTx(@[note.id, note.id], @[mkNote(100, pkSeed = 2)])
      genesis = createGenesisBlock(minimalSignedTx()).get
      blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
      res = validate(genesis, blk)
    check:
      res.isErr
      res.error.kind == BlockValidationErrorKind.StatelessTxRejected
      res.error.statelessError == StatelessLedgerError.DoubleSpend

  test "Tier 3: Pass 2 rejects heavy ZK transaction with invalid proof after light txs pass":
    let
      validLightTx = minimalSignedTx()
      genesis = createGenesisBlock(validLightTx).get
      claimTx = SignedMantleTx(
        tx: MantleTx(ops: @[createLeaderClaimOp(LeaderClaimPayload(
          rewardsRoot: default(RewardsRoot),
        ))]),
        opProofs: @[OpProof(kind: opfLeaderClaim, proofOfClaimProof: DefaultCompressedGroth16Proof)],
      )
      blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [validLightTx, claimTx])
      res = validate(genesis, blk)
    check:
      res.isErr
      res.error.kind == BlockValidationErrorKind.StatelessTxRejected
      res.error.statelessError in {StatelessLedgerError.InvalidProof, StatelessLedgerError.VerifierNotInitialised}

  test "Tier 3: PoL verification failure rejects block before stateless tx validation":
    proc failingPolVerifier(
        proof: ProofOfLeadership, public: LeaderPublic
    ): Result[bool, PolLoadError] =
      ok(false)

    let
      # A transaction that would fail stateless validation (duplicate inputs)
      note = mkUtxo(value = 100, pkSeed = 1)
      badTx = mkTransferTx(@[note.id, note.id], @[mkNote(100, pkSeed = 2)])
      genesis = createGenesisBlock(minimalSignedTx()).get
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      state = LedgerState.fromGenesis(
        testGenesisTx(), default(FieldElement), testSdpRegistry(), testLedgerConfig
      ).expect("genesis state")
      ledger = Ledger[BlockId].init(gid, state, testLedgerConfig, failingPolVerifier)
      blk = childBlock(genesis.header, gid, SlotNumber(1), [badTx])
      (admittedBlk, isOrphan) = validateBlockHeaderAndTopology(blk, tree, ledger).expect("header valid")
    check not isOrphan
    let res = validatePolAndStatelessTransactions(admittedBlk, ledger, blk.txs.asSeq)
    check:
      res.isErr
      # PoL failure at Tier 3a triggers HeaderRejected, BEFORE reaching Tier 3b StatelessTxRejected
      res.error.kind == BlockValidationErrorKind.HeaderRejected
      res.error.ledgerError == LedgerError.InvalidProofOfLeadership

  test "reconstructBlock reconstructs block from proposal":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(SignedMantleTx(testGenesisTx())).get
      gid = blockId(genesis.header)
      proposal = childProposal(genesis.header, gid, SlotNumber(1), [sm])
      mempool = Mempool.init()
    check mempool.add(ValidSignedMantleTx(sm), SlotNumber(0)).get

    let blk = reconstructBlock(proposal, mempool).get
    check blk.txs.len == 1

  test "reconstructBlock rejects if referenced transaction is missing from mempool":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(SignedMantleTx(testGenesisTx())).get
      gid = blockId(genesis.header)
      proposal = childProposal(genesis.header, gid, SlotNumber(1), [sm])
      mempool = Mempool.init()
      res = reconstructBlock(proposal, mempool)
    check res.isErr and res.error == ProposalValidationError.MissingReference

  test "mempool identifies known valid transactions":
    let
      mempool = Mempool.init()
      tx = minimalSignedTx()
    check:
      not mempool.isKnownValid(tx)
      mempool.add(ValidSignedMantleTx(tx), SlotNumber(0)).get
      mempool.isKnownValid(tx)

    # If proof differs, isKnownValid returns false
    var badProofTx = tx
    badProofTx.opProofs = @[defaultOpProofForOpcode(OpChannelInscribe).get]
    check not mempool.isKnownValid(badProofTx)

  test "validatePolAndStatelessTransactions fast-paths with unverified txs":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm).get
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      blk = childBlock(genesis.header, gid, SlotNumber(1), [sm])
      state = LedgerState.fromGenesis(
        testGenesisTx(), default(FieldElement), testSdpRegistry(), testLedgerConfig
      ).expect("genesis state")
      ledger = Ledger[BlockId].init(gid, state, testLedgerConfig, mockVerifyLeaderProof)
      mempool = Mempool.init()
    check mempool.add(ValidSignedMantleTx(sm), SlotNumber(0)).get

    let unverified = mempool.unverifiedTxs(blk.txs.asSeq)
    check unverified.len == 0
    let (admittedBlk2, isOrphan2) = validateBlockHeaderAndTopology(blk, tree, ledger).expect("header valid")
    check:
      not isOrphan2
      validatePolAndStatelessTransactions(admittedBlk2, ledger, unverified).isOk

  test "prepareBlockUpdate rejects stateful transaction failures":
    let
      sm = minimalSignedTx()
      valid = testGenesisTx()
      genesis = createGenesisBlock(SignedMantleTx(valid)).get
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      blk = childBlock(genesis.header, gid, SlotNumber(1), [sm])
      
    var state = LedgerState.fromGenesis(
        valid, default(FieldElement), testSdpRegistry(),
        testLedgerConfig).expect("genesis state")
    # Non-zero base fee causes minimalSignedTx with 0 transfer balance to fail fee coverage
    state.feeMarket.executionBaseFee = 1000
    state.feeMarket.storageGasPrice = 1000
    let
      ledger = Ledger[BlockId].init(gid, state, testLedgerConfig, mockVerifyLeaderProof)
      (admittedBlk3, isOrphan3) = validateBlockHeaderAndTopology(blk, tree, ledger).expect("header valid")
    check not isOrphan3
    let
      (validBlk, headerState) = validatePolAndStatelessTransactions(admittedBlk3, ledger, []).expect("header state")
      res = prepareBlockUpdate(validBlk, ledger, headerState)
    check res.isErr and res.error.kind == BlockValidationErrorKind.TransactionsRejected

  test "Tier 1: validateBlockHeaderAndTopology marks isOrphan as true and bypasses PoL/txs for orphan":
    const orphanParent = Hash32([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    let
      # An orphan with invalid tx that would fail stateless validation if executed
      note = mkUtxo(value = 100, pkSeed = 1)
      badTx = mkTransferTx(@[note.id, note.id], @[mkNote(100, pkSeed = 2)])
      genesis = createGenesisBlock(minimalSignedTx()).get
      tree = newLocalTree(genesis, 1'u64)
      state = LedgerState.fromGenesis(
        testGenesisTx(), default(FieldElement), testSdpRegistry(), testLedgerConfig
      ).expect("genesis state")
      ledger = Ledger[BlockId].init(blockId(genesis.header), state, testLedgerConfig, mockVerifyLeaderProof)
      blk = childBlock(genesis.header, orphanParent, SlotNumber(1), [badTx])
      # Ingestion skips Tier 3 PoL & tx checks for orphans
      res = validateBlockHeaderAndTopology(blk, tree, ledger)
    check res.get.isOrphan == true

{.pop.}
