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
  minilru,
  ../../logos_chain/core/crypto/types,
  ../../logos_chain/core/mantle/primitives,
  ../../logos_chain/core/types,
  ../../logos_chain/mempool,
  ./mantle/test_helpers,
  ../testutil

suite "mempool":
  test "mempool lifecycle (add, contains, get, len)":
    var m = Mempool.init()
    check m.len == 0

    let
      tx1 = minimalValidSignedTx()
      hash1 = tx1.hash

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
    check m.get(missingHash).error == MempoolError.TxNotFound

  test "mempool gracefully handles backward slot clock skew":
    var m = Mempool.init()
    let
      tx1 = mkValidTxWithOps(1, 1)
      tx2 = mkValidTxWithOps(1, 2)

    # Add first tx at slot 5
    check m.add(tx1, SlotNumber(5)) == true

    # Add second tx at slot 4 (simulating backward NTP slew) - should clamp to slot 5 without asserting
    check m.add(tx2, SlotNumber(4)) == true
    check m.len == 2

  test "pruneTxs removes committed transactions":
    var m = Mempool.init()
    let
      tx1 = mkValidTxWithOps(1, 1)
      tx2 = mkValidTxWithOps(1, 2)

    check m.add(tx1, SlotNumber(0)) == true
    check m.add(tx2, SlotNumber(0)) == true

    m.pruneTxs([tx1])

    check tx1.hash notin m.txs
    check tx1.hash in m
    check m.get(tx1.hash).isOk
    check tx2.hash in m
    check m.len == 1

  test "pruneExpiredTxs purges transactions older than MempoolMaxAgeSlots":
    var m = Mempool.init()
    let
      tx1 = mkValidTxWithOps(1, 1)
      tx2 = mkValidTxWithOps(1, 2)
      tx3 = mkValidTxWithOps(1, 3)

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
    check tx1.hash notin m.txs
    check tx1.hash in m
    check tx2.hash in m
    check tx3.hash in m
    # Expired tx moved to graceCache
    check m.get(tx1.hash).isOk

    # At slot 125: tx2 expired (125 > 20 + 100), tx3 remains
    m.pruneExpiredTxs(SlotNumber(125))
    check m.len == 1
    check tx2.hash notin m.txs
    check tx2.hash in m
    check tx3.hash in m

    # At slot 135: all expired
    m.pruneExpiredTxs(SlotNumber(135))
    check m.len == 0

  test "capacity limit evicts oldest tx to graceCache":
    var m = Mempool.init(capacity = 2)
    let tx1 = mkValidTxWithOps(1, 1)
    let tx2 = mkValidTxWithOps(1, 2)
    let tx3 = mkValidTxWithOps(1, 3)

    check m.add(tx1, SlotNumber(1)) == true
    check m.add(tx2, SlotNumber(2)) == true
    check m.len == 2

    # Adding 3rd transaction evicts tx1 (oldest) to graceCache
    check m.add(tx3, SlotNumber(3)) == true
    check m.len == 2
    check tx1.hash notin m.txs
    check tx1.hash in m
    check tx2.hash in m
    check tx3.hash in m
    check m.get(tx1.hash).isOk

    # Re-adding tx1 (currently in graceCache) removes it from grace and promotes back to active txs
    check m.add(tx1, SlotNumber(4)) == true
    check tx1.hash in m.txs

  test "add handles non-monotonic backwards slots by clamping to lastAddedSlot":
    var m = Mempool.init()
    let tx1 = mkValidTxWithOps(1, 1)
    let tx2 = mkValidTxWithOps(1, 2)

    check m.add(tx1, SlotNumber(10)) == true
    check m.lastAddedSlot == SlotNumber(10)

    # Adding with a backwards slot (e.g. NTP slew) clamps to lastAddedSlot (10)
    check m.add(tx2, SlotNumber(5)) == true
    check m.lastAddedSlot == SlotNumber(10)
    check m.get(tx2.hash).isOk

  test "getKnownValid matrix (D2)":
    var m = Mempool.init(capacity = 2)
    let
      vtx1 = mkValidTxWithOps(1, 1)
      vtx2 = mkValidTxWithOps(1, 2)
      vtx3 = mkValidTxWithOps(1, 3)
      nilM: Mempool = nil

    # 1. Empty or nil mempool returns none
    check m.getKnownValid(vtx1.hashed).isNone
    check nilM.getKnownValid(vtx1.hashed).isNone

    # Add vtx1 to mempool
    check m.add(vtx1, SlotNumber(1)) == true

    # 2. Same ref hits
    check m.getKnownValid(vtx1.hashed).isSome

    # 3. Equal but distinct ref hits
    let vtx1Clone = mkHashedSignedTx(vtx1.hashed.signedTx, vtx1.hash)
    check m.getKnownValid(vtx1Clone).isSome

    # 4. Same hash with different proofs misses (consensus critical!)
    var badProofStx = vtx1.hashed.signedTx
    badProofStx.opProofs = @[OpProof(kind: opfChannelInscribe, ed25519SigProof: Ed25519Signature(data: [0xFF'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))]
    let badProofHtx = mkHashedSignedTx(badProofStx, vtx1.hash)
    check m.getKnownValid(badProofHtx).isNone

    # 5. Grace cache hit works: add vtx2 and vtx3 to evict vtx1 into grace cache
    check m.add(vtx2, SlotNumber(2)) == true
    check m.add(vtx3, SlotNumber(3)) == true
    # Capacity is 2, so vtx1 was evicted into graceCache
    check vtx1.hash notin m.txs
    check m.graceCache.peek(vtx1.hash).isSome
    check m.getKnownValid(vtx1.hashed).isSome

{.pop.}
