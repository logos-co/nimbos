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
  ../../logos_chain/core/[types, mempool]

suite "core/mempool":
  test "mempool lifecycle (add, contains, get, remove, len)":
    var m = Mempool.init()
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

    # Remove transaction
    check m.remove(hash1) == true
    check m.len == 0
    check hash1 notin m

    # Double remove
    check m.remove(hash1) == false

  test "selectTxsForProposal FIFO ordering":
    var m = Mempool.init()
    
    let tx1 = minimalSignedTx()
    var tx2 = minimalSignedTx()
    tx2.tx.ops.add(createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(ZkPublicKey),
    )))
    
    check m.add(tx1) == true
    check m.add(tx2) == true

    # Selection returns both in FIFO order (tx1 then tx2)
    let selectedAll = m.selectTxsForProposal()
    check selectedAll.len == 2
    check mantleTxHash(selectedAll[0].tx) == mantleTxHash(tx1.tx)
    check mantleTxHash(selectedAll[1].tx) == mantleTxHash(tx2.tx)

  test "pruneQueue retains active transactions after removal":
    var m = Mempool.init()
    let tx1 = minimalSignedTx()
    var tx2 = minimalSignedTx()
    tx2.tx.ops.add(createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(ZkPublicKey),
    )))

    check m.add(tx1) == true
    check m.add(tx2) == true

    # Remove tx1 and manually trigger pruneQueue
    check m.remove(mantleTxHash(tx1.tx)) == true
    m.pruneQueue()

    # selectTxsForProposal must still return tx2
    let remaining = m.selectTxsForProposal()
    check remaining.len == 1
    check mantleTxHash(remaining[0].tx) == mantleTxHash(tx2.tx)
