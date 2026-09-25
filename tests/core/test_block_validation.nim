# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/sequtils,
  bearssl/rand,
  libp2p/crypto/ed25519/ed25519,
  unittest2,
  ../../logos_chain/chain/[block_validation, genesis, proposal],
  ../../logos_chain/core/[local_tree, types],
  ../../logos_chain/core/mantle/[opcodes, operations, proofs, tx_hashing, tx_types, tx_validation],
  ../../logos_chain/ledger/ledger,
  ../../logos_chain/mempool,
  ./mantle/test_helpers,
  ../testutil
from ../../logos_chain/core/crypto/types import FieldElement
from ../../logos_chain/core/mantle/primitives import MaxBlockTxs, SlotNumber
from ../ledger/sdp/test_helpers import testSdpRegistry
from ../ledger/test_helpers import testLedgerConfig

const inscribeTxFraming = 166
  ## OpCount, Opcode, ChannelId, the u32 inscription length, Parent, Signer
  ## and the 64-byte Ed25519 proof — everything but the inscription itself.

proc mkSizedTx(bytes: int): ValidSignedMantleTx =
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
    txHash = mantleTxHash(tx)
    sig = sign(kp.seckey, txHash)
    stx = SignedMantleTx(
      tx: tx,
      opProofs: @[OpProof(kind: opfChannelInscribe, ed25519SigProof: sig)],
    )
  ValidSignedMantleTx(signedTx: stx, hash: txHash)

proc validate(genesis: ValidBlock, blk: Block): Result[ValidBlock, BlockValidationError] =
  let tree = newLocalTree(genesis, 1'u64)
  let ledger = Ledger[BlockId].init(blockId(genesis.header), default(LedgerState), default(LedgerConfig))
  let (vtxs, unverified) = Mempool.init().classifyBlockTxs(blk.txs)
  let (validBlk, _) = ?validateBlock(blk, tree, ledger, vtxs, unverified)
  ok(validBlk)

proc treeWithLib(genesis: ValidBlock): tuple[tree: LocalTree, b1, b2: Block] =
  ## Tree with security parameter 1 holding genesis, b1, b2, b3; the LIB is b2.
  let
    sm = minimalValidSignedTx()
    tree = newLocalTree(genesis, 1'u64)
    b1 = childValidBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b2 = childValidBlock(b1.header, blockId(b1.header), SlotNumber(2), [sm])
    b3 = childValidBlock(b2.header, blockId(b2.header), SlotNumber(3), [sm])
  for blk in [b1, b2, b3]:
    check tree.addBlockToTree(blk)
    tree.tryUpdateLib()
  check tree.latestImmutableBlockId == blockId(b2.header)
  (tree, b1.toBlock(), b2.toBlock())

proc childProposal(
    parentHdr: Header,
    parentId: BlockId,
    slot: SlotNumber,
    txs: openArray[ValidSignedMantleTx],
): Proposal =
  var proofOfLeadership = parentHdr.proofOfLeadership
  proofOfLeadership.leaderKey = testBlockKeyPair.pubkey

  let h = initHeader(
    bedrockVersion = parentHdr.bedrockVersion,
    parentBlock = parentId,
    slot = slot,
    txHashes = txs.mapIt(it.hash),
    proofOfLeadership = proofOfLeadership,
  )
  let sig = testBlockKeyPair.seckey.sign(blockId(h))
  var refs: References
  for i, tx in txs:
    refs[i] = tx.hash
  initProposal(h, refs, sig)

suite "core/block_validation":
  test "accepts a structurally valid block":
    let
      sm = minimalValidSignedTx()
      genesis = createGenesisBlock(sm)
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    check validate(genesis, b1).isOk

  test "rejects wrong bedrock version":
    let
      sm = minimalValidSignedTx()
      genesis = createGenesisBlock(sm)
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.header.bedrockVersion = 99'u8
    check validate(genesis, b1).isErr

  test "rejects a block root that disagrees with the transactions":
    let
      sm = minimalValidSignedTx()
      genesis = createGenesisBlock(sm)
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.header.blockRoot[0] = b1.header.blockRoot[0] xor 0xff'u8
    check validate(genesis, b1).isErr

  test "rejects a transaction with mismatched ops and opProofs counts":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm.signedTx
    badTx.opProofs.add(badTx.opProofs[0]) # 1 op, 2 proofs
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [ValidSignedMantleTx(signedTx: badTx, hash: sm.hash)])
    check validate(genesis, b1).isErr

  test "rejects a transaction with unsupported opcode":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm.signedTx
    badTx.tx.ops[0].opcode = cast[Opcode](0xff'u8)
    let badHash = mantleTxHash(badTx.tx)
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [ValidSignedMantleTx(signedTx: badTx, hash: badHash)])
    check validate(genesis, b1).isErr

  test "rejects a transaction with opcode mismatching payload":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm.signedTx
    badTx.tx.ops[0].opcode = OpChannelInscribe
    let badHash = mantleTxHash(badTx.tx)
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [ValidSignedMantleTx(signedTx: badTx, hash: badHash)])
    check validate(genesis, b1).isErr

  test "rejects a transaction with proof kind mismatching opcode":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm.signedTx
    badTx.opProofs[0] = OpProof(kind: opfChannelInscribe,
        ed25519SigProof: default(Ed25519SigProof))
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [ValidSignedMantleTx(signedTx: badTx, hash: sm.hash)])
    check validate(genesis, b1).isErr

suite "core/block_validation — inclusive size and count bounds":
  test "a block whose tx bytes are exactly MaxBlockSize is accepted":
    let
      genesis = createGenesisBlock(minimalValidSignedTx())
      # Only the serialized transactions count; header and block signature don't.
      tx = mkSizedTx(MaxBlockSize)
    check encodeSignedMantleTx(tx.signedTx).len == MaxBlockSize
    let b1 = childBlock(
      genesis.header, blockId(genesis.header), SlotNumber(1), [tx])
    check validate(genesis, b1).isOk

  test "one byte past MaxBlockSize is rejected":
    let
      genesis = createGenesisBlock(minimalValidSignedTx())
      tx = mkSizedTx(MaxBlockSize + 1)
      b1 = childBlock(
        genesis.header, blockId(genesis.header), SlotNumber(1), [tx])
    check validate(genesis, b1).isErr

  test "a block with exactly MaxBlockTxs transactions is accepted":
    let
      genesis = createGenesisBlock(minimalValidSignedTx())
      txs = newSeqWith(MaxBlockTxs, minimalValidSignedTx())
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), txs)
    check validate(genesis, b1).isOk

  test "one transaction past MaxBlockTxs is rejected":
    let
      genesis = createGenesisBlock(minimalValidSignedTx())
      txs = newSeqWith(MaxBlockTxs, minimalValidSignedTx())
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), txs)
      overLong = Block(
        header: b1.header,
        signature: b1.signature,
        txs: newSeqWith(MaxBlockTxs + 1, minimalValidSignedTx().signedTx),
      )
    check validate(genesis, overLong).isErr

suite "core/block_validation — multi-tier evaluation order":
  test "header signature failure short-circuits with InvalidBlockStructure":
    let
      genesis = createGenesisBlock(minimalValidSignedTx())
      badBody = MantleTx(ops: @[createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[Note(value: 0, zkPublicKey: default(ZkPublicKey))]),
      ))])
      badTx = SignedMantleTx(
        tx: badBody,
        opProofs: @[OpProof(kind: opfTransfer, transferProof: DefaultZkSignature)],
      )
    var blk = childBlock(
      genesis.header, blockId(genesis.header), SlotNumber(1),
      [ValidSignedMantleTx(signedTx: badTx, hash: mantleTxHash(badBody))])
    # Corrupt block header signature
    blk.signature.data[0] = blk.signature.data[0] xor 0xff'u8
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.InvalidBlockStructure

  test "light-first scanning rejects malformed non-ZK tx before ZK txs":
    let
      badBody = MantleTx(ops: @[createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[]),
      ))])
      badLightTx = SignedMantleTx(
        tx: badBody,
        opProofs: @[OpProof(kind: opfTransfer, transferProof: DefaultZkSignature)],
      )
      validLightTx = minimalValidSignedTx()
      genesis = createGenesisBlock(validLightTx)
      blk = childBlock(
        genesis.header, blockId(genesis.header), SlotNumber(1),
        [validLightTx, ValidSignedMantleTx(signedTx: badLightTx, hash: mantleTxHash(badBody))])
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.StatelessTxRejected
    check res.error.statelessError == StatelessLedgerError.EmptyInputs

  test "Tier 0: rejects block with default zero signature":
    let
      genesis = createGenesisBlock(minimalValidSignedTx())
      sm = minimalValidSignedTx()
    var blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    blk.signature = DefaultEd25519Signature
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.InvalidBlockStructure

  test "Tier 1: rejects block with unknown parent":
    let
      genesis = createGenesisBlock(minimalValidSignedTx())
      sm = minimalValidSignedTx()
      missingParentId = default(BlockId)
      blk = childBlock(genesis.header, missingParentId, SlotNumber(1), [sm])
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.UnviableFork

  test "Tier 1: rejects block with non-advancing slot (slot <= parent.slot)":
    let
      genesis = createGenesisBlock(minimalValidSignedTx())
      sm = minimalValidSignedTx()
      # Genesis is slot 0; a child at slot 0 does not advance
      blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(0), [sm])
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.InvalidBlockStructure

  test "Tier 1: rejects a block extending an ancestor below the LIB":
    let
      genesis = createGenesisBlock(minimalValidSignedTx())
      (tree, b1, _) = treeWithLib(genesis)
      ledger = Ledger[BlockId].init(
        blockId(genesis.header), default(LedgerState), default(LedgerConfig))
      # b1 is below the LIB with no ledger state, but the tree still holds it.
      blk = childBlock(b1.header, blockId(b1.header), SlotNumber(4), [minimalValidSignedTx()])
      (vtxs, unverified) = Mempool.init().classifyBlockTxs(blk.txs)
      res = validateBlock(blk, tree, ledger, vtxs, unverified)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.UnviableFork

  test "Tier 1: accepts a child of the LIB":
    let
      genesis = createGenesisBlock(minimalValidSignedTx())
      (tree, _, b2) = treeWithLib(genesis)
      blk = childBlock(b2.header, blockId(b2.header), SlotNumber(4), [minimalValidSignedTx()])
    var ledger = Ledger[BlockId].init(
      blockId(genesis.header), default(LedgerState), default(LedgerConfig))
    ledger.commitUpdate(blockId(b2.header), default(LedgerState))
    let (vtxs, unverified) = Mempool.init().classifyBlockTxs(blk.txs)
    check validateBlock(blk, tree, ledger, vtxs, unverified).isOk

  test "Tier 2: rejects block with empty leader key":
    let
      genesis = createGenesisBlock(minimalValidSignedTx())
      sm = minimalValidSignedTx()
    var blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    blk.header.proofOfLeadership.leaderKey = DefaultEd25519PublicKey
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.InvalidBlockStructure

  test "Tier 3: rejects transaction with duplicate input noteIds (double spend)":
    let
      note = mkUtxo(value = 100, pkSeed = 1)
      badTx = mkTransferTx(@[note.id, note.id], @[mkNote(100, pkSeed = 2)])
      genesis = createGenesisBlock(minimalValidSignedTx())
      blk = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.StatelessTxRejected
    check res.error.statelessError == StatelessLedgerError.DoubleSpend

  test "Tier 3: Pass 2 rejects heavy ZK transaction with invalid proof after light txs pass":
    let
      validLightTx = minimalValidSignedTx()
      genesis = createGenesisBlock(validLightTx)
      claimBody = MantleTx(ops: @[createLeaderClaimOp(LeaderClaimPayload(
        rewardsRoot: default(RewardsRoot),
      ))])
      claimTx = SignedMantleTx(
        tx: claimBody,
        opProofs: @[OpProof(kind: opfLeaderClaim, proofOfClaimProof: DefaultCompressedGroth16Proof)],
      )
      blk = childBlock(
        genesis.header, blockId(genesis.header), SlotNumber(1),
        [validLightTx, ValidSignedMantleTx(signedTx: claimTx, hash: mantleTxHash(claimBody))])
    let res = validate(genesis, blk)
    check res.isErr
    check res.error.kind == BlockValidationErrorKind.StatelessTxRejected
    check res.error.statelessError in {StatelessLedgerError.InvalidProof, StatelessLedgerError.VerifierNotInitialised}

  test "reconstructBlock reconstructs block from proposal":
    let
      sm = minimalValidSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      proposal = childProposal(genesis.header, gid, SlotNumber(1), [sm])
    
    var mempool = Mempool.init()
    check mempool.add(sm, SlotNumber(0))
    let res = reconstructBlock(proposal, mempool)
    check res.isOk
    let blk = res.get
    check blk.txs.len == 1

  test "reconstructBlock rejects if referenced transaction is missing from mempool":
    let
      sm = minimalValidSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      proposal = childProposal(genesis.header, gid, SlotNumber(1), [sm])
      mempool = Mempool.init()
      
    let res = reconstructBlock(proposal, mempool)
    check res.isErr and res.error == ProposalValidationError.MissingReference

  test "mempool identifies known valid transactions":
    var mempool = Mempool.init()
    let tx = minimalValidSignedTx()
    let txHash = tx.hash
    check not mempool.isKnownValid(tx.signedTx, txHash)
    check mempool.add(tx, SlotNumber(0))
    check mempool.isKnownValid(tx.signedTx, txHash)

    # If proof differs, isKnownValid returns false
    var badProofTx = tx.signedTx
    badProofTx.opProofs = @[defaultOpProofForOpcode(OpChannelInscribe)]
    check not mempool.isKnownValid(badProofTx, txHash)

  test "validateBlock fast-paths with unverified txs":
    let
      sm = minimalValidSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      blk = childBlock(genesis.header, gid, SlotNumber(1), [sm])
      ledger = Ledger[BlockId].init(gid, default(LedgerState), default(LedgerConfig))
    var mempool = Mempool.init()
    check mempool.add(sm, SlotNumber(0))

    let (vtxs, unverified) = mempool.classifyBlockTxs(blk.txs)
    check unverified.len == 0
    check vtxs.len == 1
    check validateBlock(blk, tree, ledger, vtxs, unverified).isOk

  test "prepareBlockUpdate rejects stateful transaction failures":
    let
      sm = minimalValidSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      blk = childBlock(genesis.header, gid, SlotNumber(1), [sm])
      
    var state = LedgerState.fromGenesis(
        genesis.txs, default(FieldElement), testSdpRegistry(),
        testLedgerConfig).expect("genesis state")
    # Non-zero base fee causes minimalValidSignedTx with 0 transfer balance to fail fee coverage
    state.feeMarket.executionBaseFee = 1000
    state.feeMarket.storageGasPrice = 1000
    let ledger = Ledger[BlockId].init(gid, state, testLedgerConfig, mockVerifyLeaderProof)
    let (vtxs1, unverified1) = Mempool.init().classifyBlockTxs(blk.txs)
    let (validBlk, _) = validateBlock(blk, tree, ledger, vtxs1, unverified1).expect("valid block")
    let res = prepareBlockUpdate(validBlk, ledger)
    check res.isErr and res.error.kind == BlockValidationErrorKind.TransactionsRejected

  test "Tier 1: validateBlock marks isOrphan as true for valid orphan block":
    let
      sm = minimalValidSignedTx()
      genesis = createGenesisBlock(sm)
      tree = newLocalTree(genesis, 1'u64)
      ledger = Ledger[BlockId].init(blockId(genesis.header), default(LedgerState), default(LedgerConfig))
      orphanParent = Hash32([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
      blk = childBlock(genesis.header, orphanParent, SlotNumber(1), [sm])
    let (vtxs2, unverified2) = Mempool.init().classifyBlockTxs(blk.txs)
    let res = validateBlock(blk, tree, ledger, vtxs2, unverified2)
    check res.isOk
    let (validBlk, isOrphan) = res.get
    check isOrphan
    check validBlk.header == blk.header

{.pop.}
