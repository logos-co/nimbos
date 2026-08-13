# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/times,
  unittest2,
  ../testutil,
  ../../logos_chain/core/types,
  ../../logos_chain/core/mempool,
  ../../logos_chain/consensus/clock

suite "core/mempool":
  test "mempool lifecycle (add, contains, get, len)":
    let now = uint64(max(getTime().toUnix(), 0'i64))
    var m = Mempool.init(SlotConfig(genesisTime: now, slotDurationSeconds: 1'u64))
    check m.len == 0

    let tx1 = minimalSignedTx()
    let hash1 = mantleTxHash(tx1.tx)

    # Add transaction
    check m.add(tx1) == true
    check m.len == 1
    check hash1 in m

    let got1 = m.get(hash1).get()
    check got1.tx.ops.len == tx1.tx.ops.len

    # Duplicate add
    check m.add(tx1) == false
    check m.len == 1

    # Fetch missing transaction
    var missingHash: Hash32
    missingHash[0] = 99'u8
    check m.get(missingHash).isErr
    check m.get(missingHash).error == MempoolError.TxNotFound

  test "pruneBlockTxs removes committed block transactions":
    let now = uint64(max(getTime().toUnix(), 0'i64))
    var m = Mempool.init(SlotConfig(genesisTime: now, slotDurationSeconds: 1'u64))
    let tx1 = minimalSignedTx()
    var tx2 = minimalSignedTx()
    tx2.tx.ops.add(createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(ZkPublicKey),
    )))

    check m.add(tx1) == true
    check m.add(tx2) == true

    var blk: Block
    blk.txs = @[tx1]

    m.pruneBlockTxs(blk)

    check mantleTxHash(tx1.tx) notin m
    check mantleTxHash(tx2.tx) in m
    check m.len == 1

  test "pruneExpiredTxs purges transactions older than MempoolMaxAgeSlots":
    let now = uint64(max(getTime().toUnix(), 0'i64))
    var m = Mempool.init(SlotConfig(genesisTime: now, slotDurationSeconds: 1'u64))
    let tx1 = minimalSignedTx()

    check m.add(tx1) == true

    # Simulate 115 seconds passing
    m.slotConfig.genesisTime = now - 115'u64

    m.pruneExpiredTxs()
    check m.len == 0
