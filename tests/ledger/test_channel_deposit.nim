# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[os, strutils],
  unittest2,
  results,
  ../../logos_chain/ledger/
    [channel_state, cryptarchia_state, locked_notes, mantle_state, types],
  ../../logos_chain/core/mantle/[primitives, operations, proofs],
  ../../logos_chain/zk/zksign,
  ../zk/[snarkjs_helpers, zksign_helpers],
  ../core/mantle/test_helpers

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  zksignFixtureDir = testsDir / "../fixtures/zksign"
  fixtureVk = zksignFixtureDir / "verification_key.json"
  fixtureProof = zksignFixtureDir / "proof.json"
  fixturePublic = zksignFixtureDir / "public.json"

proc mkChanStore(cid: ChannelId, balance = TokenValue(0)): ChannelStore =
  HashTrieMap[ChannelId, ChannelState].init().insert(
    cid,
    ChannelState(
      accreditedKeys: @[],
      configurationThreshold: 1,
      withdrawThreshold: 1,
      balance: balance,
      withdrawalNonce: 0,
    ),
  )

proc mkMantle(cid: ChannelId, balance = TokenValue(0)): MantleState =
  MantleState(channels: mkChanStore(cid, balance))

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
        chans, cs, LockedNotes.init(), op,
        default(ZkSigProof), mkTxHash())
    check r.error == ChannelNotFound

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
        chans, cs, LockedNotes.init(), op,
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
        chans, cs, LockedNotes.init(), op,
        default(ZkSigProof), mkTxHash())
    check r.error == InvalidNote

  test "locked input → LockedNote":
    let
      cid = mkChannelId(4)
      chans = mkChanStore(cid)
      input = mkUtxo(value = 100, pkSeed = 1)
      cs = CryptarchiaState.init([input])
      locked = LockedNotes.init([input.id])
      op = ChannelDepositPayload(
        channel: cid, inputs: @[input.id], metadata: @[],
      )
      r = validateChannelDeposit(
        chans, cs, locked, op,
        default(ZkSigProof), mkTxHash())
    check r.error == LockedNote

suite "applyChannelDeposit — mutation and overflow (no verify)":
  test "happy: inputs consumed, channel balance credited":
    let
      cid = mkChannelId(5)
      chans = mkChanStore(cid)
      input = mkUtxo(value = 100, pkSeed = 1)
      cs = CryptarchiaState.init([input])
      op = ChannelDepositPayload(
        channel: cid, inputs: @[input.id], metadata: @[],
      )
      r = applyChannelDeposit(chans, cs, op)
    check r.isOk
    let (newChans, newCs) = r.get
    check newCs.len == 0
    check newChans.getOrDefault(cid).balance == 100

  test "balance overflow on channel credit → BalanceOverflow":
    let
      cid = mkChannelId(6)
      chans = mkChanStore(cid, balance = high(uint64) - 50)
      input = mkUtxo(value = 100, pkSeed = 1)
      cs = CryptarchiaState.init([input])
      op = ChannelDepositPayload(
        channel: cid, inputs: @[input.id], metadata: @[],
      )
      r = applyChannelDeposit(chans, cs, op)
    check r.error == BalanceOverflow

suite "MantleState.tryApplyChannelDeposit — verify wrapper (fixture-driven)":
  test "verify before VK install → VerifierNotInitialised":
    zksign.resetVkForTesting()
    let
      cid = mkChannelId(7)
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
      cid = mkChannelId(8)
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
    let (newMs, newCs) = r.get
    check newMs.channels.getOrDefault(cid).balance == 100
    check newCs.len == 0

{.pop.}
