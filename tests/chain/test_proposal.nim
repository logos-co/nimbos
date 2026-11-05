# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[os, strutils, tables],
  results,
  libp2p/crypto/ed25519/ed25519,
  unittest2,
  ../../logos_chain/chain/chain,
  ../../logos_chain/core/types,
  ../../logos_chain/core/crypto/types,
  ../../logos_chain/core/mantle/[operations, primitives, proofs, tx_types],
  ../core/mantle/test_helpers,
  ../ledger/[sdp/test_helpers, test_helpers],
  ../zk/zksign_helpers,
  ../testutil

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  zksignFixtureVk = testsDir / "../fixtures/zksign/verification_key.json"

suite "chain/proposal":
  test "selectTxsForProposal lazily caches byteSize and execGas":
    var m = Mempool.init()
    let tx1 = mkValidTxWithOps(1, 1)
    check m.add(tx1, SlotNumber(1)) == true

    # Initially metrics are uncomputed (Opt.none)
    check m.txs[tx1.hash].byteSize.isNone
    check m.txs[tx1.hash].execGas.isNone

    var state = testGenesisLedgerState()
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    let (_, count) = m.selectProposalReferences(
      state, testLedgerConfig, SlotNumber(10), verifyPoq = acceptAllPoq)
    check count == 1

    # After selection, metrics are cached
    check m.txs[tx1.hash].byteSize.isSome
    check m.txs[tx1.hash].execGas.isSome
    check m.txs[tx1.hash].byteSize.get == tx1.byteLen

  test "selectProposalReferences enforces maxBytes budget":
    var m = Mempool.init()
    let
      tx1 = mkValidTxWithOps(1, 1)
      tx2 = mkValidTxWithOps(1, 2)

    check m.add(tx1, SlotNumber(1)) == true
    check m.add(tx2, SlotNumber(2)) == true

    var state = testGenesisLedgerState()
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    let
      tx1Bytes = tx1.byteLen
      tx2Bytes = tx2.byteLen

    # With byte limit allowing only 1 tx
    let (refs, count) = m.selectProposalReferences(
      state, testLedgerConfig, SlotNumber(10),
      maxBytes = tx1Bytes + tx2Bytes - 1, verifyPoq = acceptAllPoq
    )
    check count == 1
    check refs[0] == tx1.hash

    # With byte limit allowing both txs
    let (refsAll, countAll) = m.selectProposalReferences(
      state, testLedgerConfig, SlotNumber(10),
      maxBytes = tx1Bytes + tx2Bytes, verifyPoq = acceptAllPoq
    )
    check countAll == 2
    check refsAll[0] == tx1.hash
    check refsAll[1] == tx2.hash

  test "selectProposalReferences stops search after MaxConsecutiveCandidateMisses":
    var m = Mempool.init()
    let
      initialTx = mkValidTxWithOps(1, 1)
      initialTxBytes = initialTx.byteLen
    check m.add(initialTx, SlotNumber(1)) == true

    # Add 10 oversized transactions that exceed budget (10 consecutive misses)
    for i in 2 .. 11:
      let overTx = mkValidTxWithOps(50, i)
      check m.add(overTx, SlotNumber(1)) == true

    # Add 1 tiny transaction at the end that would fit within budget if search continued
    let
      tinyTx = mkValidTxWithOps(1, 12)
      tinyTxBytes = tinyTx.byteLen
    check m.add(tinyTx, SlotNumber(1)) == true

    var state = testGenesisLedgerState()
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    let (refs, count) = m.selectProposalReferences(
      state, testLedgerConfig, SlotNumber(10),
      maxBytes = initialTxBytes + tinyTxBytes, verifyPoq = acceptAllPoq,
    )
    # Search terminated after MaxConsecutiveCandidateMisses (10 misses), tinyTx was not evaluated
    check count == 1
    check refs[0] == initialTx.hash

  test "selectProposalReferences continues search when misses < MaxConsecutiveCandidateMisses":
    var m = Mempool.init()
    let
      initialTx = mkValidTxWithOps(1, 1)
      initialTxBytes = initialTx.byteLen
    check m.add(initialTx, SlotNumber(1)) == true

    # Add 9 oversized transactions that exceed budget (9 misses < MaxConsecutiveCandidateMisses)
    for i in 2 .. 10:
      let overTx = mkValidTxWithOps(50, i)
      check m.add(overTx, SlotNumber(1)) == true

    # Add 1 tiny transaction at the end that fits within budget
    let
      tinyTx = mkValidTxWithOps(1, 11)
      tinyTxBytes = tinyTx.byteLen
    check m.add(tinyTx, SlotNumber(1)) == true

    var state = testGenesisLedgerState()
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    let (refs, count) = m.selectProposalReferences(
      state, testLedgerConfig, SlotNumber(10),
      maxBytes = initialTxBytes + tinyTxBytes, verifyPoq = acceptAllPoq,
    )
    # Search did not cut off (9 misses < 10), so tinyTx was evaluated and included
    check count == 2
    check refs[0] == initialTx.hash
    check refs[1] == tinyTx.hash

  proc testTransientRetention(
      transientTx: ValidSignedMantleTx,
      setupState: proc(s: var LedgerState) {.gcsafe, raises: [].} = nil,
  ) =
    var m = Mempool.init()
    var state = testGenesisLedgerState()
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    if setupState != nil:
      setupState(state)

    check m.add(transientTx, SlotNumber(1)) == true
    check m.len == 1

    let (_, count) = m.selectProposalReferences(
      state, testLedgerConfig, SlotNumber(10), verifyPoq = acceptAllPoq,
    )
    # Not selected because prerequisite condition is not yet satisfied
    check count == 0

    # Transient transaction is NOT purged; it remains in active mempool for subsequent blocks
    check transientTx.hash in m.txs
    check m.len == 1

  test "selectTxsForProposal retains transactions with transient InvalidNote in mempool":
    let
      u = mkUtxo(value = 100, pkSeed = 1, opIdSeed = 99)
      pk = mkZkPubKey(1)
      # txTransient spends note 'u.id' which does not exist in genesis state (InvalidNote)
      txTransient = mkValidTransferTx([u.id], [Note(value: 50, zkPublicKey: pk)])
    testTransientRetention(txTransient)

  test "selectTxsForProposal retains transactions with transient InvalidParent in mempool":
    var
      cid: ChannelId
      parentHash: Hash32
    cid[0] = 42
    parentHash[0] = 99 # Non-zero parent for brand-new channel -> InvalidParent (parent tip not confirmed yet)
    let
      payload = ChannelInscribePayload(
        channelId: cid,
        inscription: @[byte 0x01, 0x02],
        parent: parentHash,
        signer: testTxKeyPair.pubkey,
      )
      op = createChannelInscribeOp(payload)
      mtx = MantleTx(ops: @[op])
      txHash = mantleTxHash(mtx).get
      sig = sign(testTxKeyPair.seckey, txHash)
      txTransient = SignedMantleTx(
        tx: mtx,
        opProofs: @[OpProof(kind: opfChannelInscribe, ed25519SigProof: sig)],
      )
    testTransientRetention(mkValidTx(mkHashedSignedTx(txTransient, txHash)))

  test "selectTxsForProposal retains transactions with state-dependent InvalidTxProof in mempool":
    var cid: ChannelId
    cid[0] = 77
    let
      kp1 = testTxKeyPair
      op = ChannelConfigPayload(
        channel: cid, keys: @[kp1.pubkey],
        configurationThreshold: 1, transferThreshold: 1,
      )
      proof = ChannelMultiSigProof(
        signatures: @[sign(kp1.seckey, default(Hash32))],
        indexes: @[ChannelKeyIndex(99)],
      )
      tx = SignedMantleTx(
        tx: MantleTx(ops: @[createChannelConfigOp(op)]),
        opProofs: @[OpProof(kind: opfChannelConfig, channelConfigOpProof: proof)],
      )
    testTransientRetention(
      mkValidTx(tx),
      setupState = proc(s: var LedgerState) =
        s.mantleLedger = seedMantle(cid, [kp1.pubkey], transferThreshold = 1)
    )

  test "selectProposalReferences evicts transactions with permanent PermanentInvalidTxProof from mempool":
    check installZksignVk(zksignFixtureVk)
    var m = Mempool.init()
    var state = testGenesisLedgerState()
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    let u = mkUtxo(value = 100, pkSeed = 1, opIdSeed = 42)
    state.cryptarchiaLedger = state.cryptarchiaLedger.insertMintedUtxos(@[u])

    let pk = mkZkPubKey(1)
    # txInvalid spends note 'u.id' which exists in state, but carries default (all-zero) ZkSigProof,
    # causing LedgerError.PermanentInvalidTxProof during tryApplyTx
    let txInvalid = mkValidTransferTx([u.id], [Note(value: 50, zkPublicKey: pk)])
    check:
      m.add(txInvalid, SlotNumber(1)) == true
      txInvalid.hash in m
      m.len == 1

    let (_, count) = m.selectProposalReferences(
      state, testLedgerConfig, SlotNumber(10), verifyPoq = acceptAllPoq,
    )
    # Transaction rejected from proposal
    check count == 0

    # Cryptographically invalid transaction is permanently evicted from mempool
    check:
      txInvalid.hash notin m.txs
      txInvalid.hash notin m
      m.len == 0

  test "constructProposal selects from mempool, creates header, and signs with leader key":
    var m = Mempool.init()
    let tx = mkValidTxWithOps(1, 1)
    check m.add(tx, SlotNumber(1)) == true

    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
    var state = testGenesisLedgerState()
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    var pol = default(ProofOfLeadership)
    pol.leaderKey = testTxKeyPair.pubkey

    let proposal = m.constructProposal(
      tipLedgerState = state,
      cfg = testLedgerConfig,
      currentSlot = SlotNumber(10),
      parentBlock = gid,
      proofOfLeadership = pol,
      leaderSecKey = testTxKeyPair.seckey,
      verifyPoq = acceptAllPoq,
    )
    check proposal.header.slot == SlotNumber(10)
    check proposal.header.parentBlock == gid
    check proposal.header.proofOfLeadership.leaderKey == testTxKeyPair.pubkey
    check proposal.references[0] == tx.hash
    check proposal.uncleHeaders.len == 0
    check verify_signature(proposal.header, proposal.signature)

    # Reconstruct the proposal
    let reconstructedRes = reconstructProposalTxs(proposal, m)
    check reconstructedRes.isOk
    let txs = reconstructedRes.get()
    check txs.len == 1
    check txs[0].hash == tx.hash

  test "reconstructProposalTxs succeeds for orphan proposal":
    var m = Mempool.init()
    let tx = mkValidTxWithOps(1, 1)
    check m.add(tx, SlotNumber(1)) == true
    var state = testGenesisLedgerState()
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0
    let orphanParent = Hash32([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    var pol = default(ProofOfLeadership)
    pol.leaderKey = testTxKeyPair.pubkey
    let proposal = m.constructProposal(
      tipLedgerState = state,
      cfg = testLedgerConfig,
      currentSlot = SlotNumber(10),
      parentBlock = orphanParent,
      proofOfLeadership = pol,
      leaderSecKey = testTxKeyPair.seckey,
      verifyPoq = acceptAllPoq,
    )
    let res = reconstructProposalTxs(proposal, m)
    check res.isOk
    let txs = res.get
    check txs.len == 1
    check txs[0].hash == tx.hash
    # Pointer identity verified against mempool entry
    let mempoolTx = m.get(tx.hash).get
    check cast[pointer](txs[0].hashed) == cast[pointer](mempoolTx.hashed)

  test "reconstructProposalTxs rejects missing reference":
    let
      m = Mempool.init()
      tx = mkValidTxWithOps(1, 1)
      genesis = testGenesisBlock()
    var
      pol = default(ProofOfLeadership)
      refs: References
    pol.leaderKey = testTxKeyPair.pubkey
    refs[0] = tx.hash
    let h = initHeader(
      bedrockVersion = ExpectedBedrockVersion,
      parentBlock = blockId(genesis.header),
      slot = SlotNumber(10),
      uncleHeaders = [],
      txHashes = [tx.hash],
      proofOfLeadership = pol,
    )
    let sig = testTxKeyPair.seckey.sign(blockId(h))
    let proposal = initProposal(h, [], refs, sig)
    let res = reconstructProposalTxs(proposal, m)
    check res.isErr
    check res.error == ProposalValidationError.MissingReference

  test "reconstructProposalTxs preserves ValidSignedMantleTx typestate":
    var m = Mempool.init()
    let tx = mkValidTxWithOps(1, 1)
    check m.add(tx, SlotNumber(1)) == true
    var state = testGenesisLedgerState()
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    var pol = default(ProofOfLeadership)
    pol.leaderKey = testTxKeyPair.pubkey

    let proposal = m.constructProposal(
      tipLedgerState = state,
      cfg = testLedgerConfig,
      currentSlot = SlotNumber(10),
      parentBlock = default(BlockId),
      proofOfLeadership = pol,
      leaderSecKey = testTxKeyPair.seckey,
      verifyPoq = acceptAllPoq,
    )

    let validTxsRes = reconstructProposalTxs(proposal, m)
    check validTxsRes.isOk
    let validTxs = validTxsRes.get()
    check validTxs.len == 1
    check validTxs[0].hash == tx.hash
    check cast[pointer](validTxs[0].hashed) == cast[pointer](tx.hashed)

  test "admitProposal validates references and reconstructs into Block":
    var m = Mempool.init()
    let tx = mkValidTxWithOps(1, 1)
    check m.add(tx, SlotNumber(1)) == true
    var state = testGenesisLedgerState()
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0
    let
      genesis = testGenesisBlock()
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      ledger = Ledger[BlockId].init(gid, state, testLedgerConfig, mockVerifyLeaderProof)

    var pol = default(ProofOfLeadership)
    pol.leaderKey = testTxKeyPair.pubkey

    let proposal = m.constructProposal(
      tipLedgerState = state,
      cfg = testLedgerConfig,
      currentSlot = SlotNumber(10),
      parentBlock = gid,
      proofOfLeadership = pol,
      leaderSecKey = testTxKeyPair.seckey,
      verifyPoq = acceptAllPoq,
    )

    let validTxsRes = reconstructProposalTxs(proposal, m)
    check validTxsRes.isOk
    let validTxs = validTxsRes.get()

    let admissionRes = admitProposal(proposal, validTxs)
    check admissionRes.isOk
    let
      admittedBlk = admissionRes.get()
      isOrphanRes = checkTopology(proposal.header, tree, ledger)
    check isOrphanRes.isOk
    check isOrphanRes.get() == TopologyStatus.ParentPresent
    check admittedBlk.header == proposal.header
    check admittedBlk.signature == proposal.signature
    check admittedBlk.validTxs.len == 1
    check admittedBlk.validTxs[0].hash == tx.hash
    check cast[pointer](admittedBlk.validTxs[0].hashed) == cast[pointer](tx.hashed)

    let polRes = validatePolAndStatelessTransactions(admittedBlk, ledger, m)
    check polRes.isOk
    let (validBlk, _) = polRes.get()
    check validBlk.header == proposal.header
    check validBlk.signature == proposal.signature
    check validBlk.txs.len == 1
    check validBlk.txs[0].hash == tx.hash
    check cast[pointer](validBlk.txs[0].hashed) == cast[pointer](tx.hashed)

{.pop.}
