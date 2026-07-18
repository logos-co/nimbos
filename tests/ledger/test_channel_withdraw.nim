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
  results,
  bearssl/rand,
  libp2p/crypto/ed25519/ed25519,
  ../../logos_chain/ledger/
    [channel_state, cryptarchia_state, leader_state, mantle_state, types],
  ../../logos_chain/core/mantle/[primitives, operations, proofs],
  ../core/mantle/test_helpers

proc seedMantle(
    cid: ChannelId,
    keys: openArray[Ed25519PublicKey],
    balance = TokenValue(500),
    withdrawalNonce = uint32(0),
    withdrawThreshold = WithdrawThreshold(2),
): MantleState =
  MantleState(
    channels: HashTrieMap[ChannelId, ChannelState].init().insert(
      cid,
      ChannelState(
        accreditedKeys: @keys,
        configurationThreshold: 2,
        withdrawThreshold: withdrawThreshold,
        balance: balance,
        withdrawalNonce: withdrawalNonce,
      ),
    )
  )

suite "MantleState.tryApplyChannelWithdraw":
  test "happy path: 2-of-2 signatures, balance drains, nonce bumps":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(7)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey])
      cs = CryptarchiaState.init()
      txHash = mkTxHash()
      op = ChannelWithdrawPayload(
        channel: cid,
        outputs: @[mkNote(200, pkSeed = 9)],
        opIdNonce: 0,
      )
      proof = ChannelWithdrawOpProof(
        signatures: @[sign(kp1.seckey, txHash), sign(kp2.seckey, txHash)],
        indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(1)],
      )
      r = m.tryApplyChannelWithdraw(cs, op, proof, txHash)
    check r.isOk
    let (newMs, newCs) = r.get
    let chan = newMs.channels.getOrDefault(cid)
    check chan.balance == 300
    check chan.withdrawalNonce == 1
    check newCs.len == 1

  test "channel doesn't exist → ChannelNotFound":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(8)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey])
      cs = CryptarchiaState.init()
      op = ChannelWithdrawPayload(
        channel: mkChannelId(0xFF),
        outputs: @[mkNote(10, pkSeed = 1)],
        opIdNonce: 0,
      )
      r = m.tryApplyChannelWithdraw(cs, op, ChannelWithdrawOpProof(), mkTxHash())
    check r.error == ChannelNotFound

  test "wrong nonce → InvalidWithdrawNonce":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(9)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey])
      cs = CryptarchiaState.init()
      op = ChannelWithdrawPayload(
        channel: cid,
        outputs: @[mkNote(10, pkSeed = 1)],
        opIdNonce: 99,
      )
      r = m.tryApplyChannelWithdraw(cs, op, ChannelWithdrawOpProof(), mkTxHash())
    check r.error == InvalidWithdrawNonce

  test "outputs > balance → InsufficientBalance":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(10)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey])
      cs = CryptarchiaState.init()
      op = ChannelWithdrawPayload(
        channel: cid,
        outputs: @[mkNote(9999, pkSeed = 1)],
        opIdNonce: 0,
      )
      r = m.tryApplyChannelWithdraw(cs, op, ChannelWithdrawOpProof(), mkTxHash())
    check r.error == InsufficientBalance

  test "signature count != withdrawThreshold → ThresholdUnmet":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(11)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey])
      cs = CryptarchiaState.init()
      txHash = mkTxHash()
      op = ChannelWithdrawPayload(
        channel: cid,
        outputs: @[mkNote(10, pkSeed = 1)],
        opIdNonce: 0,
      )
      proof = ChannelWithdrawOpProof(
        signatures: @[sign(kp1.seckey, txHash)],
        indexes: @[ChannelKeyIndex(0)],
      )
      r = m.tryApplyChannelWithdraw(cs, op, proof, txHash)
    check r.error == ThresholdUnmet

  test "OOB sig index → InvalidProof":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(12)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey])
      cs = CryptarchiaState.init()
      txHash = mkTxHash()
      op = ChannelWithdrawPayload(
        channel: cid,
        outputs: @[mkNote(10, pkSeed = 1)],
        opIdNonce: 0,
      )
      proof = ChannelWithdrawOpProof(
        signatures: @[sign(kp1.seckey, txHash), sign(kp2.seckey, txHash)],
        indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(99)],
      )
      r = m.tryApplyChannelWithdraw(cs, op, proof, txHash)
    check r.error == InvalidProof

  test "tampered signature → InvalidProof":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(13)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey])
      cs = CryptarchiaState.init()
      txHash = mkTxHash()
      op = ChannelWithdrawPayload(
        channel: cid,
        outputs: @[mkNote(10, pkSeed = 1)],
        opIdNonce: 0,
      )
      proof = ChannelWithdrawOpProof(
        signatures: @[
          sign(kp1.seckey, mkTxHash(seed = 0xEE)),
          sign(kp2.seckey, txHash),
        ],
        indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(1)],
      )
      r = m.tryApplyChannelWithdraw(cs, op, proof, txHash)
    check r.error == InvalidProof

  test "zero-value output → ZeroValueNote":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(14)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey])
      cs = CryptarchiaState.init()
      op = ChannelWithdrawPayload(
        channel: cid,
        outputs: @[mkNote(0, pkSeed = 1)],
        opIdNonce: 0,
      )
      r = m.tryApplyChannelWithdraw(cs, op, ChannelWithdrawOpProof(), mkTxHash())
    check r.error == ZeroValueNote

  test "nonce at uint32.high → WithdrawNonceOverflow":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(15)
      m = seedMantle(
        cid, [kp1.pubkey, kp2.pubkey], withdrawalNonce = high(uint32))
      cs = CryptarchiaState.init()
      txHash = mkTxHash()
      op = ChannelWithdrawPayload(
        channel: cid,
        outputs: @[mkNote(10, pkSeed = 1)],
        opIdNonce: high(uint32),
      )
      proof = ChannelWithdrawOpProof(
        signatures: @[sign(kp1.seckey, txHash), sign(kp2.seckey, txHash)],
        indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(1)],
      )
      r = m.tryApplyChannelWithdraw(cs, op, proof, txHash)
    check r.error == WithdrawNonceOverflow

suite "applyChannelWithdraw — preserves leader":
  test "LeaderState survives mutation":
    let
      cid = mkChannelId(20)
      chans = HashTrieMap[ChannelId, ChannelState].init().insert(
        cid,
        ChannelState(
          accreditedKeys: @[],
          configurationThreshold: 1,
          withdrawThreshold: 1,
          balance: 100,
          withdrawalNonce: 0,
        ),
      )
      leader = LeaderState.init().recordBlockLeader(default(RewardVoucher), 42)
        .addEpochVouchers(1'u64)
      cs = CryptarchiaState(utxos: UtxoStore.init(), leader: leader)
      op = ChannelWithdrawPayload(
        channel: cid,
        outputs: @[mkNote(50, pkSeed = 1)],
        opIdNonce: 0,
      )
      (_, newCs) = applyChannelWithdraw(chans, cs, op)
    check newCs.leader == leader

{.pop.}
