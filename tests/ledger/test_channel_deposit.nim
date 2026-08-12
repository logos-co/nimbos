# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[os, sets, strutils],
  unittest2,
  results,
  ../../logos_chain/ledger/
    [channel_state, cryptarchia_state, leader_state, mantle_state, types],
  ../../logos_chain/core/mantle/[primitives, operations, proofs, tx_hashing, utxo],
  ../../logos_chain/zk/zksign,
  ../zk/[snarkjs_helpers, zksign_helpers],
  ../core/mantle/test_helpers

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  zksignFixtureDir = testsDir / "../fixtures/zksign"
  fixtureVk = zksignFixtureDir / "verification_key.json"
  fixtureProof = zksignFixtureDir / "proof.json"
  fixturePublic = zksignFixtureDir / "public.json"

proc mkChanStore(cid: ChannelId): ChannelStore =
  HashTrieMap[ChannelId, ChannelState].init().insert(
    cid,
    ChannelState(
      accreditedKeys: @[],
      configurationThreshold: 1,
      transferThreshold: 1,
    ),
  )

proc mkMantle(cid: ChannelId): MantleState =
  MantleState(channels: mkChanStore(cid), channelNotes: ChannelNotes.init())

suite "validateChannelDeposit — structural checks (no VK)":
  # These paths all short-circuit before sig verify, so a default sig is
  # enough. VK install is only needed for the happy-path suite below.
  test "channel doesn't exist → ChannelNotFound":
    let
      cid = mkChannelId(1)
      chans = mkChanStore(cid)
      input = mkUtxo(value = 100, pkSeed = 1)
      cs = CryptarchiaState.init([input])
      op = ChannelDepositPayload(
        channel: mkChannelId(0xFF),
        inputs: @[input.id],
        metadata: @[],
      )
      r = validateChannelDeposit(
        chans, ChannelNotes.init(), cs, LockedNotes.init(), op,
        default(ZkSigProof), mkTxHash())
    check r.error == ChannelNotFound

  test "no inputs → EmptyInputs":
    let
      cid = mkChannelId(2)
      chans = mkChanStore(cid)
      input = mkUtxo(value = 100, pkSeed = 1)
      cs = CryptarchiaState.init([input])
      op = ChannelDepositPayload(channel: cid, inputs: @[], metadata: @[])
      r = validateChannelDeposit(
        chans, ChannelNotes.init(), cs, LockedNotes.init(), op,
        default(ZkSigProof), mkTxHash())
    check r.error == EmptyInputs

  test "duplicate input NoteId → DoubleSpend":
    let
      cid = mkChannelId(2)
      chans = mkChanStore(cid)
      input = mkUtxo(value = 100, pkSeed = 1)
      cs = CryptarchiaState.init([input])
      op = ChannelDepositPayload(
        channel: cid, inputs: @[input.id, input.id], metadata: @[],
      )
      r = validateChannelDeposit(
        chans, ChannelNotes.init(), cs, LockedNotes.init(), op,
        default(ZkSigProof), mkTxHash())
    check r.error == DoubleSpend

  test "missing input UTXO → InvalidNote":
    let
      cid = mkChannelId(3)
      chans = mkChanStore(cid)
      missing = mkUtxo(value = 1, pkSeed = 7)
      cs = CryptarchiaState.init()
      op = ChannelDepositPayload(
        channel: cid, inputs: @[missing.id], metadata: @[],
      )
      r = validateChannelDeposit(
        chans, ChannelNotes.init(), cs, LockedNotes.init(), op,
        default(ZkSigProof), mkTxHash())
    check r.error == InvalidNote

  test "locked input → LockedNote":
    let
      cid = mkChannelId(4)
      chans = mkChanStore(cid)
      input = mkUtxo(value = 100, pkSeed = 1)
      cs = CryptarchiaState.init([input])
      op = ChannelDepositPayload(
        channel: cid, inputs: @[input.id], metadata: @[],
      )
      locked = LockedNotes.init().insert(input.id, initHashSet[DeclarationId]())
      r = validateChannelDeposit(
        chans, ChannelNotes.init(), cs, locked, op,
        default(ZkSigProof), mkTxHash())
    check r.error == LockedNote

  test "input already owned by a channel → ChannelNoteSpend":
    let
      cid = mkChannelId(5)
      chans = mkChanStore(cid)
      input = mkUtxo(value = 100, pkSeed = 1)
      cs = CryptarchiaState.init([input])
      notes = ChannelNotes.init().registerChannelNote(input.id, cid)
        .expect("fresh note")
      op = ChannelDepositPayload(
        channel: cid, inputs: @[input.id], metadata: @[],
      )
      r = validateChannelDeposit(
        chans, notes, cs, LockedNotes.init(), op,
        default(ZkSigProof), mkTxHash())
    check r.error == ChannelNoteSpend

suite "applyChannelDeposit — consume and re-create (no verify)":
  test "inputs are spent and re-minted as channel notes under the deposit OpId":
    let
      cid = mkChannelId(6)
      in0 = mkUtxo(value = 100, pkSeed = 1)
      in1 = mkUtxo(value = 250, pkSeed = 2)
      cs = CryptarchiaState.init([in0, in1])
      op = ChannelDepositPayload(
        channel: cid, inputs: @[in0.id, in1.id], metadata: @[],
      )
      r = applyChannelDeposit(ChannelNotes.init(), cs, op)
    check r.isOk
    let
      (notes, newCs) = r.get
      recreated0 = Utxo(opId: opId(op), outputIndex: 0, note: in0.note)
      recreated1 = Utxo(opId: opId(op), outputIndex: 1, note: in1.note)
    check newCs.len == 2
    check not newCs.utxos.contains(in0.id)
    check not newCs.utxos.contains(in1.id)
    # Value and ZkPublicKey survive; only the NoteId is new, which restarts
    # ageing and stops the signed deposit from being replayed.
    check newCs.utxos.get(recreated0.id) == Opt.some(recreated0)
    check newCs.utxos.get(recreated1.id) == Opt.some(recreated1)
    check notes.isChannelNoteOf(recreated0.id, cid)
    check notes.isChannelNoteOf(recreated1.id, cid)
    check notes.len == 2

  test "deposit → withdraw → replaying the deposit fails on the spent input":
    let
      cid = mkChannelId(7)
      input = mkUtxo(value = 100, pkSeed = 1)
      chans = mkChanStore(cid)
      cs = CryptarchiaState.init([input])
      depositOp = ChannelDepositPayload(
        channel: cid, inputs: @[input.id], metadata: @[],
      )
      deposited = applyChannelDeposit(ChannelNotes.init(), cs, depositOp)
        .expect("deposit applies")
      channelNote = Utxo(opId: opId(depositOp), outputIndex: 0, note: input.note)
      withdrawOp = ChannelWithdrawPayload(
        channel: cid, inputs: @[channelNote.id])
      released = applyChannelWithdraw(deposited.channelNotes, withdrawOp)
        .expect("owned by cid")
      replay = validateChannelDeposit(
        chans, released, deposited.cs, LockedNotes.init(), depositOp,
        default(ZkSigProof), mkTxHash())
    check replay.error == InvalidNote

  test "preserves LeaderState":
    let
      cid = mkChannelId(8)
      input = mkUtxo(value = 100, pkSeed = 1)
      leader = LeaderState.init().recordBlockLeader(default(RewardVoucher))
        .addPendingRewards(42).addEpochVouchers().get
      cs = CryptarchiaState(
        utxos: UtxoStore.init().insert(input.id, input).store, leader: leader,
      )
      op = ChannelDepositPayload(
        channel: cid, inputs: @[input.id], metadata: @[],
      )
      r = applyChannelDeposit(ChannelNotes.init(), cs, op)
    check r.isOk
    check r.get.cs.leader == leader

suite "MantleState.tryApplyChannelDeposit — verify wrapper (fixture-driven)":
  test "verify before VK install → VerifierNotInitialised":
    zksign.resetVkForTesting()
    let
      cid = mkChannelId(12)
      m = mkMantle(cid)
      input = mkUtxo(value = 100, pkSeed = 1)
      cs = CryptarchiaState.init([input])
      op = ChannelDepositPayload(
        channel: cid, inputs: @[input.id], metadata: @[],
      )
      r = m.tryApplyChannelDeposit(
        cs, LockedNotes.init(), op,
        sig = default(ZkSigProof), txHash = mkTxHash())
    check r.error == VerifierNotInitialised

  test "bad signature → InvalidProof":
    check installZksignVk(fixtureVk)
    let
      cid = mkChannelId(13)
      m = mkMantle(cid)
      input = mkUtxo(value = 100, pkSeed = 1)
      cs = CryptarchiaState.init([input])
      op = ChannelDepositPayload(
        channel: cid, inputs: @[input.id], metadata: @[],
      )
      r = m.tryApplyChannelDeposit(
        cs, LockedNotes.init(), op,
        sig = default(ZkSigProof), txHash = mkTxHash())
    check r.error == InvalidProof

  test "happy: real proof + matching pks + matching msg → state advances":
    check installZksignVk(fixtureVk)
    let
      sig = loadProof(fixtureProof)
      txHash = loadTxHash(fixturePublic)
      cid = mkChannelId(9)
      m = mkMantle(cid)
      input = mkUtxoWithPk(mkRealZkPubKey(1), value = 100)
      cs = CryptarchiaState.init([input])
      op = ChannelDepositPayload(
        channel: cid, inputs: @[input.id], metadata: @[],
      )
      r = m.tryApplyChannelDeposit(cs, LockedNotes.init(), op, sig, txHash)
    check r.isOk
    let
      (newMs, newCs) = r.get
      recreated = Utxo(opId: opId(op), outputIndex: 0, note: input.note)
    check newCs.len == 1
    check not newCs.utxos.contains(input.id)
    check newCs.utxos.get(recreated.id) == Opt.some(recreated)
    check newMs.channelNotes.isChannelNoteOf(recreated.id, cid)

{.pop.}
