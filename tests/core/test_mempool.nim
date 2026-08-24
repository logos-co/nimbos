# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  ../testutil,
  ../../logos_chain/core/types,
  ../../logos_chain/core/mempool,
  ../../logos_chain/core/crypto/types,
  ../../logos_chain/core/mantle/[operations, tx_types],
  ../../logos_chain/consensus/clock,
  ../../logos_chain/core/mantle/primitives,
  ../../logos_chain/ledger/ledger,
  ../../logos_chain/chain/genesis,
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

  test "pruneBlockTxs removes committed block transactions":
    var m = Mempool.init()
    let tx1 = minimalSignedTx()
    var tx2 = minimalSignedTx()
    tx2.tx.ops.add(createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(ZkPublicKey),
    )))

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
    let tx1 = minimalSignedTx()
    var tx2 = minimalSignedTx()
    tx2.tx.ops.add(createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(ZkPublicKey),
    )))
    var tx3 = minimalSignedTx()
    tx3.tx.ops.add(createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(ZkPublicKey),
    )))
    tx3.tx.ops.add(createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(ZkPublicKey),
    )))

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
    check mantleTxHash(tx1.tx) notin m
    check mantleTxHash(tx2.tx) in m
    check mantleTxHash(tx3.tx) in m
    # Expired tx moved to graceCache
    check m.get(mantleTxHash(tx1.tx)).isOk

    # At slot 125: tx2 expired (125 > 20 + 100), tx3 remains
    m.pruneExpiredTxs(SlotNumber(125))
    check m.len == 1
    check mantleTxHash(tx2.tx) notin m
    check mantleTxHash(tx3.tx) in m

    # At slot 135: all expired
    m.pruneExpiredTxs(SlotNumber(135))
    check m.len == 0

  test "capacity limit evicts oldest tx to graceCache":
    var m = Mempool.init(capacity = 2)
    let tx1 = minimalSignedTx()
    var tx2 = minimalSignedTx()
    tx2.tx.ops.add(createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(ZkPublicKey),
    )))
    var tx3 = minimalSignedTx()
    tx3.tx.ops.add(createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(ZkPublicKey),
    )))
    tx3.tx.ops.add(createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(ZkPublicKey),
    )))

    check m.add(tx1, SlotNumber(1)) == true
    check m.add(tx2, SlotNumber(2)) == true
    check m.len == 2

    # Adding 3rd transaction evicts tx1 (oldest) to graceCache
    check m.add(tx3, SlotNumber(3)) == true
    check m.len == 2
    check mantleTxHash(tx1.tx) notin m
    check mantleTxHash(tx2.tx) in m
    check mantleTxHash(tx3.tx) in m
    check m.get(mantleTxHash(tx1.tx)).isOk

  test "add enforces monotonic slot order via doAssert":
    var m = Mempool.init()
    let tx1 = minimalSignedTx()
    var tx2 = minimalSignedTx()
    tx2.tx.ops.add(createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(ZkPublicKey),
    )))

    check m.add(tx1, SlotNumber(50)) == true

    # Adding with an older slot triggers an assertion defect
    expect(AssertionDefect):
      discard m.add(tx2, SlotNumber(49))

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
