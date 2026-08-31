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
  ../../logos_chain/ledger/[channel_state, mantle_state, types],
  ../../logos_chain/core/mantle/[primitives, operations, proofs],
  ../core/mantle/test_helpers

proc seedMantle(
    cid: ChannelId, keys: openArray[Ed25519PublicKey],
    configThreshold = ConfigurationThreshold(1),
    transferThreshold = TransferThreshold(1),
): MantleState =
  let seedOp = ChannelConfigPayload(
    channel: cid, keys: @keys,
    configurationThreshold: configThreshold,
    transferThreshold: transferThreshold,
  )
  MantleState.init().tryApplyChannelConfig(
    seedOp, ChannelMultiSigProof(), mkTxHash(), blockSlot = 0'u64,
  ).get

suite "MantleState.tryApplyChannelConfig — JIT creation":
  test "fresh channel with valid config → created with given keys/thresholds":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(1)
      op = ChannelConfigPayload(
        channel: cid,
        keys: @[kp1.pubkey, kp2.pubkey],
        postingTimeframe: 100,
        postingTimeout: 10,
        configurationThreshold: 2,
        transferThreshold: 1,
      )
      r = MantleState.init().tryApplyChannelConfig(
        op, ChannelMultiSigProof(), mkTxHash(), blockSlot = 5'u64)
    check r.isOk
    let chan = r.get.channels.getOrDefault(cid)
    check chan.accreditedKeys == @[kp1.pubkey, kp2.pubkey]
    check chan.configurationThreshold == 2
    check chan.transferThreshold == 1
    check chan.postingTimeframe == 100
    check chan.postingTimeout == 10
    check chan.tipSlot == 5'u64

  test "transferThreshold > keys.len is accepted — reconfiguration can lower it":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      op = ChannelConfigPayload(
        channel: mkChannelId(6),
        keys: @[kp1.pubkey, kp2.pubkey],
        configurationThreshold: 1,
        transferThreshold: 3,
      )
      r = MantleState.init().tryApplyChannelConfig(
        op, ChannelMultiSigProof(), mkTxHash(), blockSlot = 0'u64)
    check r.isOk
    check r.get.channels.getOrDefault(mkChannelId(6)).transferThreshold == 3

suite "MantleState.tryApplyChannelConfig — existing channel":
  test "valid threshold signatures → config overwrites accreditedKeys":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      kp3 = mkEdKeyPair(rng)
      cid = mkChannelId(10)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey], configThreshold = 2)
      txHash = mkTxHash(seed = 0x42)
      op = ChannelConfigPayload(
        channel: cid,
        keys: @[kp3.pubkey],
        configurationThreshold: 1,
        transferThreshold: 1,
      )
      proof = ChannelMultiSigProof(
        signatures: @[sign(kp1.seckey, txHash), sign(kp2.seckey, txHash)],
        indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(1)],
      )
      r = m.tryApplyChannelConfig(op, proof, txHash, blockSlot = 3'u64)
    check r.isOk
    let chan = r.get.channels.getOrDefault(cid)
    check chan.accreditedKeys == @[kp3.pubkey]
    check chan.configurationThreshold == 1

  test "signature count != configurationThreshold → ThresholdUnmet":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(11)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey], configThreshold = 2)
      txHash = mkTxHash()
      op = ChannelConfigPayload(
        channel: cid,
        keys: @[kp1.pubkey],
        configurationThreshold: 1,
        transferThreshold: 1,
      )
      proof = ChannelMultiSigProof(
        signatures: @[sign(kp1.seckey, txHash)],
        indexes: @[ChannelKeyIndex(0)],
      )
      r = m.tryApplyChannelConfig(op, proof, txHash, blockSlot = 0'u64)
    check r.error == ThresholdUnmet

  test "OOB index → InvalidTxProof":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(12)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey], configThreshold = 2)
      txHash = mkTxHash()
      op = ChannelConfigPayload(
        channel: cid, keys: @[kp1.pubkey],
        configurationThreshold: 1, transferThreshold: 1,
      )
      proof = ChannelMultiSigProof(
        signatures: @[sign(kp1.seckey, txHash), sign(kp2.seckey, txHash)],
        indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(99)],
      )
      r = m.tryApplyChannelConfig(op, proof, txHash, blockSlot = 0'u64)
    check r.error == InvalidTxProof

  test "bad signature → InvalidTxProof":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      cid = mkChannelId(13)
      m = seedMantle(cid, [kp1.pubkey, kp2.pubkey], configThreshold = 2)
      txHash = mkTxHash(seed = 0x10)
      op = ChannelConfigPayload(
        channel: cid, keys: @[kp1.pubkey],
        configurationThreshold: 1, transferThreshold: 1,
      )
      proof = ChannelMultiSigProof(
        signatures: @[
          sign(kp1.seckey, mkTxHash(seed = 0xEE)),  # wrong msg
          sign(kp2.seckey, txHash),
        ],
        indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(1)],
      )
      r = m.tryApplyChannelConfig(op, proof, txHash, blockSlot = 0'u64)
    check r.error == InvalidTxProof

{.pop.}
