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
  ../../logos_chain/core/crypto/types,
  ../../logos_chain/core/mantle/[primitives, tx_hashing, tx_types],
  ../../logos_chain/core/types,
  ../../logos_chain/mempool,
  ../testutil

suite "mempool":
  test "mempool lifecycle (add, contains, get, len)":
    var m = Mempool.init()
    check m.len == 0

    let
      tx1 = ValidSignedMantleTx(minimalSignedTx())
      hash1 = mantleTxHash(tx1.tx).get

    # Add transaction
    check m.add(tx1, SlotNumber(0)).get == true
    check m.len == 1
    check hash1 in m

    let got1 = m.get(hash1).get()
    check got1.tx.ops.len == tx1.tx.ops.len

    # Duplicate add
    check m.add(tx1, SlotNumber(0)).get == false
    check m.len == 1

    # Fetch missing transaction
    var missingHash: Hash32
    missingHash[0] = 99'u8
    check m.get(missingHash).error == MempoolError.TxNotFound

  test "mempool add returns error on malformed transaction":
    var m = Mempool.init()
    var invalidInputs: seq[NoteId]
    for i in 0 .. 255:
      invalidInputs.add(default(NoteId))
    let malformedTx = ValidSignedMantleTx(SignedMantleTx(
      tx: MantleTx(ops: @[createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: invalidInputs), outputs: Outputs(notes: @[])
      ))]),
      opProofs: @[OpProof(kind: opfTransfer, transferProof: default(ZkSigProof))]
    ))
    check m.add(malformedTx, SlotNumber(0)).error == EncodingError.InputsCountExceeded

  test "mempool gracefully handles backward slot clock skew":
    var m = Mempool.init()
    let
      tx1 = ValidSignedMantleTx(signedTxWithOps(1, 1))
      tx2 = ValidSignedMantleTx(signedTxWithOps(1, 2))

    # Add first tx at slot 5
    check m.add(tx1, SlotNumber(5)).get == true

    # Add second tx at slot 4 (simulating backward NTP slew) - should clamp to slot 5 without asserting
    check m.add(tx2, SlotNumber(4)).get == true
    check m.len == 2

  test "pruneBlockTxs removes committed block transactions":
    var m = Mempool.init()
    let
      tx1 = ValidSignedMantleTx(signedTxWithOps(1, 1))
      tx2 = ValidSignedMantleTx(signedTxWithOps(1, 2))

    check m.add(tx1, SlotNumber(0)).get == true
    check m.add(tx2, SlotNumber(0)).get == true

    var blk: Block
    blk.txs = @[SignedMantleTx(tx1)]

    m.pruneBlockTxs(blk)

    check mantleTxHash(tx1.tx).get notin m.txs
    check mantleTxHash(tx1.tx).get in m
    check m.get(mantleTxHash(tx1.tx).get).isOk
    check mantleTxHash(tx2.tx).get in m
    check m.len == 1

  test "pruneExpiredTxs purges transactions older than MempoolMaxAgeSlots":
    var m = Mempool.init()
    let
      tx1 = ValidSignedMantleTx(signedTxWithOps(1, 1))
      tx2 = ValidSignedMantleTx(signedTxWithOps(1, 2))
      tx3 = ValidSignedMantleTx(signedTxWithOps(1, 3))

    # Added at monotonically increasing slots
    check m.add(tx1, SlotNumber(10)).get == true
    check m.add(tx2, SlotNumber(20)).get == true
    check m.add(tx3, SlotNumber(30)).get == true
    check m.len == 3

    # At slot 109: none expired (tx1 expires at > 110)
    m.pruneExpiredTxs(SlotNumber(109))
    check m.len == 3

    # At slot 111: tx1 expired (111 > 10 + 100), tx2 and tx3 remain
    m.pruneExpiredTxs(SlotNumber(111))
    check m.len == 2
    check mantleTxHash(tx1.tx).get notin m.txs
    check mantleTxHash(tx1.tx).get in m
    check mantleTxHash(tx2.tx).get in m
    check mantleTxHash(tx3.tx).get in m
    # Expired tx moved to graceCache
    check m.get(mantleTxHash(tx1.tx).get).isOk

    # At slot 125: tx2 expired (125 > 20 + 100), tx3 remains
    m.pruneExpiredTxs(SlotNumber(125))
    check m.len == 1
    check mantleTxHash(tx2.tx).get notin m.txs
    check mantleTxHash(tx2.tx).get in m
    check mantleTxHash(tx3.tx).get in m

    # At slot 135: all expired
    m.pruneExpiredTxs(SlotNumber(135))
    check m.len == 0

  test "capacity limit evicts oldest tx to graceCache":
    var m = Mempool.init(capacity = 2)
    let
      tx1 = ValidSignedMantleTx(signedTxWithOps(1, 1))
      tx2 = ValidSignedMantleTx(signedTxWithOps(1, 2))
      tx3 = ValidSignedMantleTx(signedTxWithOps(1, 3))

    check m.add(tx1, SlotNumber(1)).get == true
    check m.add(tx2, SlotNumber(2)).get == true
    check m.len == 2

    # Adding 3rd transaction evicts tx1 (oldest) to graceCache
    check m.add(tx3, SlotNumber(3)).get == true
    check m.len == 2
    check mantleTxHash(tx1.tx).get notin m.txs
    check mantleTxHash(tx1.tx).get in m
    check mantleTxHash(tx2.tx).get in m
    check mantleTxHash(tx3.tx).get in m
    check m.get(mantleTxHash(tx1.tx).get).isOk

    # Re-adding tx1 (currently in graceCache) removes it from grace and promotes back to active txs
    check m.add(tx1, SlotNumber(4)).get == true
    check mantleTxHash(tx1.tx).get in m.txs

  test "add handles non-monotonic backwards slots by clamping to lastAddedSlot":
    var m = Mempool.init()
    let
      tx1 = ValidSignedMantleTx(signedTxWithOps(1, 1))
      tx2 = ValidSignedMantleTx(signedTxWithOps(1, 2))

    check m.add(tx1, SlotNumber(10)).get == true
    check m.lastAddedSlot == SlotNumber(10)

    # Adding with a backwards slot (e.g. NTP slew) clamps to lastAddedSlot (10)
    check m.add(tx2, SlotNumber(5)).get == true
    check m.lastAddedSlot == SlotNumber(10)
    check m.get(mantleTxHash(tx2.tx).get).isOk

{.pop.}
