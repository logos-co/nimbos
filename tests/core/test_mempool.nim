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
  ../../logos_chain/core/crypto/types,
  ../../logos_chain/core/mantle/[operations, proofs, tx_types, utxo],
  ../../logos_chain/core/mantle/primitives,
  ../../logos_chain/ledger/ledger,
  ../../logos_chain/chain/genesis,
  ../../logos_chain/zk/poseidon2/hasher,
  ../core/mantle/test_helpers,
  ../ledger/test_helpers,
  ../ledger/sdp/test_helpers

suite "core/mempool":
  test "mempool lifecycle (add, contains, get, len)":
    var m = Mempool.init()
    check m.len == 0

    let tx1 = minimalSignedTx()
    let hash1 = mantleTxHash(tx1.tx)

    # Add transaction
    check m.add(tx1, SlotNumber(0)) == true
    check m.len == 1
    check hash1 in m

    let got1 = m.get(hash1).get()
    check got1.tx.ops.len == tx1.tx.ops.len

    # Duplicate add
    check m.add(tx1, SlotNumber(0)) == false
    check m.len == 1

    # Fetch missing transaction
    var missingHash: Hash32
    missingHash[0] = 99'u8
    check m.get(missingHash).isErr
    check m.get(missingHash).error == MempoolError.TxNotFound

  test "mempool gracefully handles backward slot clock skew":
    var m = Mempool.init()
    let tx1 = signedTxWithOps(1, 1)
    let tx2 = signedTxWithOps(1, 2)

    # Add first tx at slot 5
    check m.add(tx1, SlotNumber(5)) == true

    # Add second tx at slot 4 (simulating backward NTP slew) - should clamp to slot 5 without asserting
    check m.add(tx2, SlotNumber(4)) == true
    check m.len == 2

  test "pruneBlockTxs removes committed block transactions":
    var m = Mempool.init()
    let tx1 = signedTxWithOps(1, 1)
    let tx2 = signedTxWithOps(1, 2)

    check m.add(tx1, SlotNumber(0)) == true
    check m.add(tx2, SlotNumber(0)) == true

    var blk: Block
    blk.txs = @[tx1]

    m.pruneBlockTxs(blk)

    check mantleTxHash(tx1.tx) notin m
    check mantleTxHash(tx2.tx) in m
    check m.len == 1

  test "pruneExpiredTxs purges transactions older than MempoolMaxAgeSlots":
    var m = Mempool.init()
    let tx1 = signedTxWithOps(1, 1)
    let tx2 = signedTxWithOps(1, 2)
    let tx3 = signedTxWithOps(1, 3)

    # Added at monotonically increasing slots
    check m.add(tx1, SlotNumber(10)) == true
    check m.add(tx2, SlotNumber(20)) == true
    check m.add(tx3, SlotNumber(30)) == true
    check m.len == 3

    # At slot 109: none expired (tx1 expires at > 110)
    m.pruneExpiredTxs(SlotNumber(109))
    check m.len == 3

    # At slot 111: tx1 expired (111 > 10 + 100), tx2 and tx3 remain
    m.pruneExpiredTxs(SlotNumber(111))
    check m.len == 2
    check mantleTxHash(tx1.tx) notin m.txs
    check mantleTxHash(tx1.tx) in m
    check mantleTxHash(tx2.tx) in m
    check mantleTxHash(tx3.tx) in m
    # Expired tx moved to graceCache
    check m.get(mantleTxHash(tx1.tx)).isOk

    # At slot 125: tx2 expired (125 > 20 + 100), tx3 remains
    m.pruneExpiredTxs(SlotNumber(125))
    check m.len == 1
    check mantleTxHash(tx2.tx) notin m.txs
    check mantleTxHash(tx2.tx) in m
    check mantleTxHash(tx3.tx) in m

    # At slot 135: all expired
    m.pruneExpiredTxs(SlotNumber(135))
    check m.len == 0

  test "capacity limit evicts oldest tx to graceCache":
    var m = Mempool.init(capacity = 2)
    let tx1 = signedTxWithOps(1, 1)
    let tx2 = signedTxWithOps(1, 2)
    let tx3 = signedTxWithOps(1, 3)

    check m.add(tx1, SlotNumber(1)) == true
    check m.add(tx2, SlotNumber(2)) == true
    check m.len == 2

    # Adding 3rd transaction evicts tx1 (oldest) to graceCache
    check m.add(tx3, SlotNumber(3)) == true
    check m.len == 2
    check mantleTxHash(tx1.tx) notin m.txs
    check mantleTxHash(tx1.tx) in m
    check mantleTxHash(tx2.tx) in m
    check mantleTxHash(tx3.tx) in m
    check m.get(mantleTxHash(tx1.tx)).isOk

    # Re-adding tx1 (currently in graceCache) removes it from grace and promotes back to active txs
    check m.add(tx1, SlotNumber(4)) == true
    check mantleTxHash(tx1.tx) in m.txs

  test "add handles non-monotonic backwards slots by clamping to lastAddedSlot":
    var m = Mempool.init()
    let tx1 = signedTxWithOps(1, 1)
    let tx2 = signedTxWithOps(1, 2)

    check m.add(tx1, SlotNumber(10)) == true
    check m.lastAddedSlot == SlotNumber(10)

    # Adding with a backwards slot (e.g. NTP slew) clamps to lastAddedSlot (10)
    check m.add(tx2, SlotNumber(5)) == true
    check m.lastAddedSlot == SlotNumber(10)
    check m.get(mantleTxHash(tx2.tx)).isOk

  test "selectTxsForProposal lazily caches byteSize and execGas":
    var m = Mempool.init()
    let tx1 = signedTxWithOps(1, 1)
    let hash1 = mantleTxHash(tx1.tx)
    check m.add(tx1, SlotNumber(1)) == true

    # Initially metrics are uncomputed (Opt.none)
    check m.txs[hash1].byteSize.isNone
    check m.txs[hash1].execGas.isNone

    let genesis = createGenesisBlock(signedTxWithOps(1, 0))
    var state = LedgerState.fromGenesis(
      genesis.txs, default(FieldElement), testSdpRegistry(),
      testLedgerConfig).expect("genesis state")
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    let selected = m.selectTxsForProposal(state, testLedgerConfig, SlotNumber(10))
    check selected.len == 1

    # After selection, metrics are cached
    check m.txs[hash1].byteSize.isSome
    check m.txs[hash1].execGas.isSome
    check m.txs[hash1].byteSize.get == encodeSignedMantleTx(tx1).len

  test "selectTxsForProposal enforces maxBytes budget":
    var m = Mempool.init()
    let tx1 = signedTxWithOps(1, 1)
    let tx2 = signedTxWithOps(1, 2)

    check m.add(tx1, SlotNumber(1)) == true
    check m.add(tx2, SlotNumber(2)) == true

    let genesis = createGenesisBlock(signedTxWithOps(1, 0))
    var state = LedgerState.fromGenesis(
      genesis.txs, default(FieldElement), testSdpRegistry(),
      testLedgerConfig).expect("genesis state")
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    let tx1Bytes = encodeSignedMantleTx(tx1).len
    let tx2Bytes = encodeSignedMantleTx(tx2).len

    # With byte limit allowing only 1 tx
    let selected = m.selectTxsForProposal(
      state, testLedgerConfig, SlotNumber(10), maxBytes = tx1Bytes + tx2Bytes - 1
    )
    check selected.len == 1
    check mantleTxHash(selected[0].tx) == mantleTxHash(tx1.tx)

    # With byte limit allowing both txs
    let selectedAll = m.selectTxsForProposal(
      state, testLedgerConfig, SlotNumber(10), maxBytes = tx1Bytes + tx2Bytes
    )
    check selectedAll.len == 2

suite "core/mempool proposal selection":
  test "selectTxsForProposal stops search after MaxConsecutiveCandidateMisses":
    var m = Mempool.init()
    let initialTx = signedTxWithOps(1, 1)
    let initialTxBytes = encodeSignedMantleTx(initialTx).len
    check m.add(initialTx, SlotNumber(1)) == true

    # Add 10 oversized transactions that exceed budget (10 consecutive misses)
    for i in 2 .. 11:
      let overTx = signedTxWithOps(50, i)
      check m.add(overTx, SlotNumber(1)) == true

    # Add 1 tiny transaction at the end that would fit within budget if search continued
    let tinyTx = signedTxWithOps(1, 12)
    let tinyTxBytes = encodeSignedMantleTx(tinyTx).len
    check m.add(tinyTx, SlotNumber(1)) == true

    let genesis = createGenesisBlock(signedTxWithOps(1, 0))
    var state = LedgerState.fromGenesis(
      genesis.txs, default(FieldElement), testSdpRegistry(),
      testLedgerConfig).expect("genesis state")
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    let selected = m.selectTxsForProposal(
      state, testLedgerConfig, SlotNumber(10),
      maxBytes = initialTxBytes + tinyTxBytes,
    )
    # Search terminated after MaxConsecutiveCandidateMisses (10 misses), tinyTx was not evaluated
    check selected.len == 1
    check mantleTxHash(selected[0].tx) == mantleTxHash(initialTx.tx)

  test "selectTxsForProposal continues search when misses < MaxConsecutiveCandidateMisses":
    var m = Mempool.init()
    let initialTx = signedTxWithOps(1, 1)
    let initialTxBytes = encodeSignedMantleTx(initialTx).len
    check m.add(initialTx, SlotNumber(1)) == true

    # Add 9 oversized transactions that exceed budget (9 misses < MaxConsecutiveCandidateMisses)
    for i in 2 .. 10:
      let overTx = signedTxWithOps(50, i)
      check m.add(overTx, SlotNumber(1)) == true

    # Add 1 tiny transaction at the end that fits within budget
    let tinyTx = signedTxWithOps(1, 11)
    let tinyTxBytes = encodeSignedMantleTx(tinyTx).len
    check m.add(tinyTx, SlotNumber(1)) == true

    let genesis = createGenesisBlock(signedTxWithOps(1, 0))
    var state = LedgerState.fromGenesis(
      genesis.txs, default(FieldElement), testSdpRegistry(),
      testLedgerConfig).expect("genesis state")
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0

    let selected = m.selectTxsForProposal(
      state, testLedgerConfig, SlotNumber(10),
      maxBytes = initialTxBytes + tinyTxBytes,
    )
    # Search did not cut off (9 misses < 10), so tinyTx was evaluated and included
    check selected.len == 2
    check mantleTxHash(selected[0].tx) == mantleTxHash(initialTx.tx)
    check mantleTxHash(selected[1].tx) == mantleTxHash(tinyTx.tx)

  proc testTransientRetention(
      transientTx: SignedMantleTx,
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

    let selected = m.selectTxsForProposal(
      state, testLedgerConfig, SlotNumber(10),
    )
    # Not selected because prerequisite condition is not yet satisfied
    check selected.len == 0

    # Transient transaction is NOT purged; it remains in active mempool for subsequent blocks
    check mantleTxHash(transientTx.tx) in m.txs
    check m.len == 1

  test "selectTxsForProposal retains transactions with transient InvalidNote in mempool":
    let u = mkUtxo(value = 100, pkSeed = 1, opIdSeed = 99)
    let pk = mkZkPubKey(1)
    # txTransient spends note 'u.id' which does not exist in genesis state (InvalidNote)
    let txTransient = mkTransferTx([u.id], [Note(value: 50, zkPublicKey: pk)])
    testTransientRetention(txTransient)

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
    testTransientRetention(txTransient)
