# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/sets,
  unittest2,
  results,
  bearssl/rand,
  libp2p/crypto/ed25519/ed25519,
  ../../logos_chain/ledger/
    [channel_state, cryptarchia_state, leader_state, mantle_state, types],
  ../../logos_chain/core/mantle/[primitives, operations, proofs, tx_hashing, utxo],
  ../core/mantle/test_helpers

from ./test_helpers import seedChannelNotes, seedMantle, twoOfTwo

suite "MantleState.tryApplyChannelTransfer":
  test "happy path: inputs consumed, outputs registered under the transfer OpId":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(1)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey], [note])
      cs = CryptarchiaState.init([note])
      txHash = mkTxHash()
      out0 = mkNote(60, pkSeed = 5)
      out1 = mkNote(40, pkSeed = 6)
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id], outputs: @[out0, out1])
      r = m.tryApplyChannelTransfer(
        cs, LockedNotes.init(), op, twoOfTwo(kp1, kp2, txHash), txHash)
    check r.isOk
    let
      (newMs, newCs) = r.get
      expected0 = Utxo(opId: opId(op), outputIndex: 0, note: out0)
      expected1 = Utxo(opId: opId(op), outputIndex: 1, note: out1)
    check newCs.len == 2
    check not newCs.utxos.contains(note.id)
    check newCs.utxos.get(expected0.id) == Opt.some(expected0)
    check newCs.utxos.get(expected1.id) == Opt.some(expected1)
    check not newMs.channelNotes.isChannelNote(note.id)
    check newMs.channelNotes.isChannelNoteOf(expected0.id, cid)
    check newMs.channelNotes.isChannelNoteOf(expected1.id, cid)

  test "outputs worth more than the inputs → UnbalancedTransfer":
    let
      cid = mkChannelId(2)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [], [note])
      cs = CryptarchiaState.init([note])
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id], outputs: @[mkNote(101, pkSeed = 5)])
      r = m.tryApplyChannelTransfer(
        cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == UnbalancedTransfer

  test "outputs worth less than the inputs → UnbalancedTransfer":
    let
      cid = mkChannelId(3)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [], [note])
      cs = CryptarchiaState.init([note])
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id], outputs: @[mkNote(99, pkSeed = 5)])
      r = m.tryApplyChannelTransfer(
        cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == UnbalancedTransfer

  test "zero-value output → ZeroValueNote":
    let
      cid = mkChannelId(4)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [], [note])
      cs = CryptarchiaState.init([note])
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id],
        outputs: @[mkNote(100, pkSeed = 5), mkNote(0, pkSeed = 6)])
      r = m.tryApplyChannelTransfer(
        cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == ZeroValueNote

  test "output sum past uint64 → BalanceOverflow":
    let
      cid = mkChannelId(5)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [], [note])
      cs = CryptarchiaState.init([note])
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id],
        outputs: @[mkNote(uint64.high, pkSeed = 5), mkNote(2, pkSeed = 6)])
      r = m.tryApplyChannelTransfer(
        cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == BalanceOverflow

  test "channel doesn't exist → ChannelNotFound":
    let
      cid = mkChannelId(6)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [], [note])
      cs = CryptarchiaState.init([note])
      op = ChannelTransferPayload(
        channel: mkChannelId(0xFF), inputs: @[note.id],
        outputs: @[mkNote(100, pkSeed = 5)])
      r = m.tryApplyChannelTransfer(
        cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == ChannelNotFound

  test "input that is not a channel note → NotAChannelNote":
    let
      cid = mkChannelId(7)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [])
      cs = CryptarchiaState.init([note])
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id], outputs: @[mkNote(100, pkSeed = 5)])
      r = m.tryApplyChannelTransfer(
        cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == NotAChannelNote

  test "input owned by another channel → NotAChannelNote":
    let
      cid = mkChannelId(8)
      note = mkUtxo(value = 100, pkSeed = 1)
      cs = CryptarchiaState.init([note])
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id], outputs: @[mkNote(100, pkSeed = 5)])
    var m = seedMantle(cid, [])
    m.channelNotes = seedChannelNotes([(note: note, channel: mkChannelId(0xB0))])
    let r = m.tryApplyChannelTransfer(
      cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == NotAChannelNote

  test "no inputs → EmptyInputs":
    # Rejected ahead of the balance check, which an all-empty op would pass.
    let
      cid = mkChannelId(9)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [], [note])
      cs = CryptarchiaState.init([note])
      op = ChannelTransferPayload(channel: cid, inputs: @[], outputs: @[])
      r = m.tryApplyChannelTransfer(
        cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == EmptyInputs

  test "duplicate input NoteId → DoubleSpend":
    let
      cid = mkChannelId(9)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [], [note])
      cs = CryptarchiaState.init([note])
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id, note.id],
        outputs: @[mkNote(200, pkSeed = 5)])
      r = m.tryApplyChannelTransfer(
        cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == DoubleSpend

  test "input missing from the UTXO set → InvalidNote":
    let
      cid = mkChannelId(10)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [], [note])
      cs = CryptarchiaState.init()
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id], outputs: @[mkNote(100, pkSeed = 5)])
      r = m.tryApplyChannelTransfer(
        cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == InvalidNote

  test "locked input → LockedNote":
    let
      cid = mkChannelId(11)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [], [note])
      cs = CryptarchiaState.init([note])
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id], outputs: @[mkNote(100, pkSeed = 5)])
      locked = LockedNotes.init().insert(note.id, initHashSet[DeclarationId]())
      r = m.tryApplyChannelTransfer(
        cs, locked, op, ChannelMultiSigProof(), mkTxHash())
    check r.error == LockedNote

  test "signature count != transferThreshold → ThresholdUnmet":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(12)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey], [note])
      cs = CryptarchiaState.init([note])
      txHash = mkTxHash()
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id], outputs: @[mkNote(100, pkSeed = 5)])
      proof = ChannelMultiSigProof(
        signatures: @[sign(kp1.seckey, txHash)],
        indexes: @[ChannelKeyIndex(0)],
      )
      r = m.tryApplyChannelTransfer(cs, LockedNotes.init(), op, proof, txHash)
    check r.error == ThresholdUnmet

  test "OOB sig index → InvalidProof":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(13)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey], [note])
      cs = CryptarchiaState.init([note])
      txHash = mkTxHash()
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id], outputs: @[mkNote(100, pkSeed = 5)])
      proof = ChannelMultiSigProof(
        signatures: @[sign(kp1.seckey, txHash), sign(kp2.seckey, txHash)],
        indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(99)],
      )
      r = m.tryApplyChannelTransfer(cs, LockedNotes.init(), op, proof, txHash)
    check r.error == InvalidProof

  test "tampered signature → InvalidProof":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(14)
      note = mkUtxo(value = 100, pkSeed = 1)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey], [note])
      cs = CryptarchiaState.init([note])
      txHash = mkTxHash()
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id], outputs: @[mkNote(100, pkSeed = 5)])
      proof = ChannelMultiSigProof(
        signatures: @[
          sign(kp1.seckey, mkTxHash(seed = 0xEE)),
          sign(kp2.seckey, txHash),
        ],
        indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(1)],
      )
      r = m.tryApplyChannelTransfer(cs, LockedNotes.init(), op, proof, txHash)
    check r.error == InvalidProof

  test "preserves LeaderState":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(15)
      note = mkUtxo(value = 100, pkSeed = 1)
      leader = LeaderState.init().recordBlockLeader(default(RewardVoucher), 42)
        .addEpochVouchers().get
      cs = CryptarchiaState(
        utxos: UtxoStore.init().insert(note.id, note).store, leader: leader)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey], [note])
      txHash = mkTxHash()
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id], outputs: @[mkNote(100, pkSeed = 5)])
      r = m.tryApplyChannelTransfer(
        cs, LockedNotes.init(), op, twoOfTwo(kp1, kp2, txHash), txHash)
    check r.isOk
    check r.get.cs.leader == leader

suite "channel notes lifecycle":
  test "deposit → transfer → withdraw → regular Transfer spends the release":
    # Drives the pure transition cores: a real deposit needs a ZkSignature
    # fixture, which the verify wrapper's own suite covers.
    let
      cid = mkChannelId(30)
      deposited = mkUtxo(value = 100, pkSeed = 1)
      depositOp = ChannelDepositPayload(
        channel: cid, inputs: @[deposited.id], metadata: @[])
      afterDeposit = applyChannelDeposit(
        ChannelNotes.init(), CryptarchiaState.init([deposited]), depositOp
      ).expect("deposit applies")
      channelNote = Utxo(
        opId: opId(depositOp), outputIndex: 0, note: deposited.note)
    check afterDeposit.channelNotes.isChannelNoteOf(channelNote.id, cid)
    check not afterDeposit.cs.utxos.contains(deposited.id)

    # Reassign the value to a sequencer-controlled key.
    let
      reassigned = mkNote(100, pkSeed = 7)
      transferOp = ChannelTransferPayload(
        channel: cid, inputs: @[channelNote.id], outputs: @[reassigned])
      afterTransfer = applyChannelTransfer(
        afterDeposit.channelNotes, afterDeposit.cs, transferOp
      ).expect("transfer applies")
      transferred = Utxo(
        opId: opId(transferOp), outputIndex: 0, note: reassigned)
    check afterTransfer.channelNotes.isChannelNoteOf(transferred.id, cid)
    check not afterTransfer.channelNotes.isChannelNote(channelNote.id)

    # Release it, then spend it as an ordinary note.
    let
      withdrawOp = ChannelWithdrawPayload(
        channel: cid, inputs: @[transferred.id])
      afterWithdraw = applyChannelWithdraw(
        afterTransfer.channelNotes, withdrawOp).expect("withdraw applies")
      spend = TransferPayload(
        inputs: Inputs(noteIds: @[transferred.id]),
        outputs: Outputs(notes: @[mkNote(100, pkSeed = 8)]),
      )
    check afterWithdraw.isEmpty
    check afterTransfer.cs.applyTransferState(
      LockedNotes.init(), afterWithdraw, spend).isOk

{.pop.}
