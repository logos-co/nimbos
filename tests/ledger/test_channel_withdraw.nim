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
  ../../logos_chain/core/mantle/[primitives, operations, proofs],
  ../core/mantle/test_helpers

from ./test_helpers import seedChannelNotes, seedMantle, twoOfTwo

suite "MantleState.tryApplyChannelWithdraw":
  test "happy path: inputs leave the channel but stay in the UTXO set":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(7)
      note = mkUtxo(value = 200, pkSeed = 9)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey], [note])
      cs = CryptarchiaState.init([note])
      txHash = mkTxHash()
      op = ChannelWithdrawPayload(channel: cid, inputs: @[note.id])
      r = m.tryApplyChannelWithdraw(
        cs, LockedNotes.init(), op, twoOfTwo(kp1, kp2, txHash), txHash)
    check r.isOk
    let released = r.get
    check not released.channelNotes.isChannelNote(note.id)
    check released.channelNotes.isEmpty
    # The note keeps its identity: same NoteId, value and key, so its ageing
    # never restarts.
    check cs.utxos.len == 1
    check cs.utxos.get(note.id) == Opt.some(note)

  test "channel doesn't exist → ChannelNotFound":
    let
      cid = mkChannelId(8)
      note = mkUtxo(value = 10, pkSeed = 1)
      m = seedMantle(cid, [], [note])
      cs = CryptarchiaState.init([note])
      op = ChannelWithdrawPayload(channel: mkChannelId(0xFF), inputs: @[note.id])
      r = m.tryApplyChannelWithdraw(
        cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == ChannelNotFound

  test "input that is not a channel note → NotAChannelNote":
    let
      cid = mkChannelId(9)
      note = mkUtxo(value = 10, pkSeed = 1)
      m = seedMantle(cid, [])
      cs = CryptarchiaState.init([note])
      op = ChannelWithdrawPayload(channel: cid, inputs: @[note.id])
      r = m.tryApplyChannelWithdraw(
        cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == NotAChannelNote

  test "input owned by another channel → NotAChannelNote":
    let
      cid = mkChannelId(10)
      other = mkChannelId(0xA0)
      note = mkUtxo(value = 10, pkSeed = 1)
      cs = CryptarchiaState.init([note])
      op = ChannelWithdrawPayload(channel: cid, inputs: @[note.id])
    var m = seedMantle(cid, [])
    m.channelNotes = seedChannelNotes([(note: note, channel: other)])
    let r = m.tryApplyChannelWithdraw(
      cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == NotAChannelNote

  test "duplicate input NoteId → DoubleSpend":
    let
      cid = mkChannelId(11)
      note = mkUtxo(value = 10, pkSeed = 1)
      m = seedMantle(cid, [], [note])
      cs = CryptarchiaState.init([note])
      op = ChannelWithdrawPayload(channel: cid, inputs: @[note.id, note.id])
      r = m.tryApplyChannelWithdraw(
        cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == DoubleSpend

  test "input missing from the UTXO set → InvalidNote":
    let
      cid = mkChannelId(12)
      note = mkUtxo(value = 10, pkSeed = 1)
      m = seedMantle(cid, [], [note])
      cs = CryptarchiaState.init()
      op = ChannelWithdrawPayload(channel: cid, inputs: @[note.id])
      r = m.tryApplyChannelWithdraw(
        cs, LockedNotes.init(), op, ChannelMultiSigProof(), mkTxHash())
    check r.error == InvalidNote

  test "locked input → LockedNote":
    let
      cid = mkChannelId(13)
      note = mkUtxo(value = 10, pkSeed = 1)
      m = seedMantle(cid, [], [note])
      cs = CryptarchiaState.init([note])
      op = ChannelWithdrawPayload(channel: cid, inputs: @[note.id])
      locked = LockedNotes.init().insert(note.id, initHashSet[DeclarationId]())
      r = m.tryApplyChannelWithdraw(
        cs, locked, op, ChannelMultiSigProof(), mkTxHash())
    check r.error == LockedNote

  test "signature count != transferThreshold → ThresholdUnmet":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(14)
      note = mkUtxo(value = 10, pkSeed = 1)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey], [note])
      cs = CryptarchiaState.init([note])
      txHash = mkTxHash()
      op = ChannelWithdrawPayload(channel: cid, inputs: @[note.id])
      proof = ChannelMultiSigProof(
        signatures: @[sign(kp1.seckey, txHash)],
        indexes: @[ChannelKeyIndex(0)],
      )
      r = m.tryApplyChannelWithdraw(cs, LockedNotes.init(), op, proof, txHash)
    check r.error == ThresholdUnmet

  test "OOB sig index → InvalidProof":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(15)
      note = mkUtxo(value = 10, pkSeed = 1)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey], [note])
      cs = CryptarchiaState.init([note])
      txHash = mkTxHash()
      op = ChannelWithdrawPayload(channel: cid, inputs: @[note.id])
      proof = ChannelMultiSigProof(
        signatures: @[sign(kp1.seckey, txHash), sign(kp2.seckey, txHash)],
        indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(99)],
      )
      r = m.tryApplyChannelWithdraw(cs, LockedNotes.init(), op, proof, txHash)
    check r.error == InvalidProof

  test "tampered signature → InvalidProof":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(16)
      note = mkUtxo(value = 10, pkSeed = 1)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey], [note])
      cs = CryptarchiaState.init([note])
      txHash = mkTxHash()
      op = ChannelWithdrawPayload(channel: cid, inputs: @[note.id])
      proof = ChannelMultiSigProof(
        signatures: @[
          sign(kp1.seckey, mkTxHash(seed = 0xEE)),
          sign(kp2.seckey, txHash),
        ],
        indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(1)],
      )
      r = m.tryApplyChannelWithdraw(cs, LockedNotes.init(), op, proof, txHash)
    check r.error == InvalidProof

suite "applyChannelWithdraw — released notes rejoin the regular note set":
  test "a released note is spendable by a regular Transfer":
    let
      cid = mkChannelId(20)
      note = mkUtxo(value = 50, pkSeed = 3)
      cs = CryptarchiaState.init([note])
      op = ChannelWithdrawPayload(channel: cid, inputs: @[note.id])
      transfer = TransferPayload(
        inputs: Inputs(noteIds: @[note.id]),
        outputs: Outputs(notes: @[mkNote(50, pkSeed = 4)]),
      )
      owned = seedChannelNotes([(note, cid)])
    check cs.applyTransferState(LockedNotes.init(), owned, transfer).error ==
      ChannelNoteSpend

    let released = applyChannelWithdraw(owned, op).expect("owned by cid")
    check cs.applyTransferState(LockedNotes.init(), released, transfer).isOk

  test "preserves LeaderState and the UTXO set":
    let
      rng = HmacDrbgContext.new()
      kp = mkEdKeyPair(rng)
      cid = mkChannelId(21)
      note = mkUtxo(value = 50, pkSeed = 1)
      leader = LeaderState.init().recordBlockLeader(default(RewardVoucher), 42)
        .addEpochVouchers().get
      cs = CryptarchiaState(
        utxos: UtxoStore.init().insert(note.id, note).store, leader: leader)
      txHash = mkTxHash()
      m = seedMantle(
        cid, [kp.pubkey], [note], transferThreshold = TransferThreshold(1))
      op = ChannelWithdrawPayload(channel: cid, inputs: @[note.id])
      proof = ChannelMultiSigProof(
        signatures: @[sign(kp.seckey, txHash)], indexes: @[ChannelKeyIndex(0)])
    check m.tryApplyChannelWithdraw(cs, LockedNotes.init(), op, proof, txHash).isOk
    check cs.leader == leader
    check cs.utxos.len == 1

{.pop.}
