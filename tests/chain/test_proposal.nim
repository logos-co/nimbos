# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/tables,
  unittest2,
  libp2p/crypto/ed25519/ed25519,
  ../testutil,
  ../../logos_chain/core/types,
  ../../logos_chain/core/mempool,
  ../../logos_chain/core/local_tree,
  ../../logos_chain/core/crypto/types,
  ../../logos_chain/core/mantle/[operations, proofs, tx_types, utxo],
  ../../logos_chain/core/mantle/primitives,
  ../../logos_chain/ledger/ledger,
  ../../logos_chain/chain/[genesis, proposal],
  ../../logos_chain/zk/poseidon2/hasher,
  ../core/mantle/test_helpers,
  ../ledger/test_helpers,
  ../ledger/sdp/test_helpers

suite "chain/proposal":
  test "selectTxsForProposal lazily caches byteSize and execGas":
    var m = Mempool.init()
    let tx1 = signedTxWithOps(1, 1)
    let hash1 = mantleTxHash(tx1.tx)
    check m.add(ValidSignedMantleTx(tx1), SlotNumber(1)) == true

    # Initially metrics are uncomputed (Opt.none)
    check m.txs[hash1].byteSize.isNone
    check m.txs[hash1].execGas.isNone

    let genesis = createGenesisBlock(signedTxWithOps(1, 0))
    var state = LedgerState.fromGenesis(
      genesis.txs, default(FieldElement), testSdpRegistry(),
      testLedgerConfig).expect("genesis state")
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    let (refs, count) = m.selectProposalReferences(state, testLedgerConfig, SlotNumber(10))
    check count == 1

    # After selection, metrics are cached
    check m.txs[hash1].byteSize.isSome
    check m.txs[hash1].execGas.isSome
    check m.txs[hash1].byteSize.get == encodeSignedMantleTx(tx1).len

  test "selectProposalReferences enforces maxBytes budget":
    var m = Mempool.init()
    let tx1 = signedTxWithOps(1, 1)
    let tx2 = signedTxWithOps(1, 2)

    check m.add(ValidSignedMantleTx(tx1), SlotNumber(1)) == true
    check m.add(ValidSignedMantleTx(tx2), SlotNumber(2)) == true

    let genesis = createGenesisBlock(signedTxWithOps(1, 0))
    var state = LedgerState.fromGenesis(
      genesis.txs, default(FieldElement), testSdpRegistry(),
      testLedgerConfig).expect("genesis state")
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    let tx1Bytes = encodeSignedMantleTx(tx1).len
    let tx2Bytes = encodeSignedMantleTx(tx2).len

    # With byte limit allowing only 1 tx
    let (refs, count) = m.selectProposalReferences(
      state, testLedgerConfig, SlotNumber(10), maxBytes = tx1Bytes + tx2Bytes - 1
    )
    check count == 1
    check refs[0] == mantleTxHash(tx1.tx)

    # With byte limit allowing both txs
    let (refsAll, countAll) = m.selectProposalReferences(
      state, testLedgerConfig, SlotNumber(10), maxBytes = tx1Bytes + tx2Bytes
    )
    check countAll == 2

  test "selectProposalReferences stops search after MaxConsecutiveCandidateMisses":
    var m = Mempool.init()
    let initialTx = signedTxWithOps(1, 1)
    let initialTxBytes = encodeSignedMantleTx(initialTx).len
    check m.add(ValidSignedMantleTx(initialTx), SlotNumber(1)) == true

    # Add 10 oversized transactions that exceed budget (10 consecutive misses)
    for i in 2 .. 11:
      let overTx = signedTxWithOps(50, i)
      check m.add(ValidSignedMantleTx(overTx), SlotNumber(1)) == true

    # Add 1 tiny transaction at the end that would fit within budget if search continued
    let tinyTx = signedTxWithOps(1, 12)
    let tinyTxBytes = encodeSignedMantleTx(tinyTx).len
    check m.add(ValidSignedMantleTx(tinyTx), SlotNumber(1)) == true

    let genesis = createGenesisBlock(signedTxWithOps(1, 0))
    var state = LedgerState.fromGenesis(
      genesis.txs, default(FieldElement), testSdpRegistry(),
      testLedgerConfig).expect("genesis state")
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    let (refs, count) = m.selectProposalReferences(
      state, testLedgerConfig, SlotNumber(10),
      maxBytes = initialTxBytes + tinyTxBytes,
    )
    # Search terminated after MaxConsecutiveCandidateMisses (10 misses), tinyTx was not evaluated
    check count == 1
    check refs[0] == mantleTxHash(initialTx.tx)

  test "selectProposalReferences continues search when misses < MaxConsecutiveCandidateMisses":
    var m = Mempool.init()
    let initialTx = signedTxWithOps(1, 1)
    let initialTxBytes = encodeSignedMantleTx(initialTx).len
    check m.add(ValidSignedMantleTx(initialTx), SlotNumber(1)) == true

    # Add 9 oversized transactions that exceed budget (9 misses < MaxConsecutiveCandidateMisses)
    for i in 2 .. 10:
      let overTx = signedTxWithOps(50, i)
      check m.add(ValidSignedMantleTx(overTx), SlotNumber(1)) == true

    # Add 1 tiny transaction at the end that fits within budget
    let tinyTx = signedTxWithOps(1, 11)
    let tinyTxBytes = encodeSignedMantleTx(tinyTx).len
    check m.add(ValidSignedMantleTx(tinyTx), SlotNumber(1)) == true

    let genesis = createGenesisBlock(signedTxWithOps(1, 0))
    var state = LedgerState.fromGenesis(
      genesis.txs, default(FieldElement), testSdpRegistry(),
      testLedgerConfig).expect("genesis state")
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    let (refs, count) = m.selectProposalReferences(
      state, testLedgerConfig, SlotNumber(10),
      maxBytes = initialTxBytes + tinyTxBytes,
    )
    # Search did not cut off (9 misses < 10), so tinyTx was evaluated and included
    check count == 2
    check refs[0] == mantleTxHash(initialTx.tx)
    check refs[1] == mantleTxHash(tinyTx.tx)

  proc testTransientRetention(
      transientTx: ValidSignedMantleTx,
      setupState: proc(s: var LedgerState) {.gcsafe, raises: [].} = nil,
  ) =
    var m = Mempool.init()
    let genesis = createGenesisBlock(signedTxWithOps(1, 0))
    var state = LedgerState.fromGenesis(
      genesis.txs, default(FieldElement), testSdpRegistry(),
      testLedgerConfig).expect("genesis state")
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    if setupState != nil:
      setupState(state)

    check m.add(transientTx, SlotNumber(1)) == true
    check m.len == 1

    let (refs, count) = m.selectProposalReferences(
      state, testLedgerConfig, SlotNumber(10),
    )
    # Not selected because prerequisite condition is not yet satisfied
    check count == 0

    # Transient transaction is NOT purged; it remains in active mempool for subsequent blocks
    check mantleTxHash(transientTx.tx) in m.txs
    check m.len == 1

  test "selectTxsForProposal retains transactions with transient InvalidNote in mempool":
    let u = mkUtxo(value = 100, pkSeed = 1, opIdSeed = 99)
    let pk = mkZkPubKey(1)
    # txTransient spends note 'u.id' which does not exist in genesis state (InvalidNote)
    let txTransient = mkTransferTx([u.id], [Note(value: 50, zkPublicKey: pk)])
    testTransientRetention(ValidSignedMantleTx(txTransient))

  test "selectTxsForProposal retains transactions with transient InvalidParent in mempool":
    var cid: ChannelId
    cid[0] = 42
    var parentHash: Hash32
    parentHash[0] = 99 # Non-zero parent for brand-new channel -> InvalidParent (parent tip not confirmed yet)
    let payload = ChannelInscribePayload(
      channelId: cid,
      inscription: @[byte 0x01, 0x02],
      parent: parentHash,
      signer: testTxKeyPair.pubkey,
    )
    let op = createChannelInscribeOp(payload)
    let mtx = MantleTx(ops: @[op])
    let txHash = mantleTxHash(mtx)
    let sig = sign(testTxKeyPair.seckey, txHash)
    let txTransient = SignedMantleTx(
      tx: mtx,
      opProofs: @[OpProof(kind: opfChannelInscribe, ed25519SigProof: sig)],
    )
    testTransientRetention(ValidSignedMantleTx(txTransient))

  test "constructProposal selects from mempool, creates header, and signs with leader key":
    var m = Mempool.init()
    let tx = signedTxWithOps(1, 1)
    check m.add(ValidSignedMantleTx(tx), SlotNumber(1)) == true

    let genesis = createGenesisBlock(signedTxWithOps(1, 0))
    let gid = blockId(genesis.header)
    var state = LedgerState.fromGenesis(
      genesis.txs, default(FieldElement), testSdpRegistry(),
      testLedgerConfig).expect("genesis state")
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
    )
    check proposal.header.slot == SlotNumber(10)
    check proposal.header.parentBlock == gid
    check proposal.header.proofOfLeadership.leaderKey == testTxKeyPair.pubkey
    check proposal.references[0] == mantleTxHash(tx.tx)

    # Reconstruct and validate the proposal
    let tree = newLocalTree(genesis, 1'u64)
    let ledger = Ledger[BlockId].init(gid, state, testLedgerConfig, mockVerifyLeaderProof)
    let reconstructedRes = reconstructAndValidateBlock(proposal, tree, ledger, m)
    check reconstructedRes.isOk
    let blk = reconstructedRes.get()
    check blk.txs.len == 1
    check mantleTxHash(blk.txs[0].tx) == mantleTxHash(tx.tx)

{.pop.}
