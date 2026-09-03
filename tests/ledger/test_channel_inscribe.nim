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
  ../../logos_chain/core/mantle/[primitives, operations, tx_hashing],
  ../core/mantle/test_helpers

suite "MantleState.tryApplyChannelInscribe — JIT creation":
  test "fresh channel with ZERO parent → created, tipMessage advanced":
    let
      rng = HmacDrbgContext.new()
      kp = mkEdKeyPair(rng)
      cid = mkChannelId(1)
      op = ChannelInscribePayload(
        channelId: cid,
        inscription: @[byte 0x68, 0x69],
        parent: default(Hash32),
        signer: kp.pubkey,
      )
      r = MantleState.init().tryApplyChannelInscribe(op, blockSlot = 7'u64)
    check r.isOk
    let chan = r.get.channels.getOrDefault(cid)
    check chan.accreditedKeys == @[kp.pubkey]
    check chan.tipMessage == opId(op)
    check chan.tipSlot == 7'u64

  test "fresh channel with non-ZERO parent → InvalidParent":
    let
      rng = HmacDrbgContext.new()
      kp = mkEdKeyPair(rng)
      cid = mkChannelId(2)
      op = ChannelInscribePayload(
        channelId: cid,
        inscription: @[byte 0x78],
        parent: mkTxHash(seed = 0x99),
        signer: kp.pubkey,
      )
      r = MantleState.init().tryApplyChannelInscribe(op, blockSlot = 0'u64)
    check r.error == InvalidParent

suite "MantleState.tryApplyChannelInscribe — existing channel":
  test "second inscribe with correct parent and signer → tipMessage advances":
    let
      rng = HmacDrbgContext.new()
      kp = mkEdKeyPair(rng)
      cid = mkChannelId(3)
      seedOp = ChannelInscribePayload(
        channelId: cid, inscription: @[byte 0x61],
        parent: default(Hash32), signer: kp.pubkey,
      )
      seedMantle = MantleState.init().tryApplyChannelInscribe(
        seedOp, blockSlot = 1'u64,
      ).get
      prevTip = seedMantle.channels.getOrDefault(cid).tipMessage
      op = ChannelInscribePayload(
        channelId: cid, inscription: @[byte 0x62],
        parent: prevTip, signer: kp.pubkey,
      )
      r = seedMantle.tryApplyChannelInscribe(op, blockSlot = 2'u64)
    check r.isOk
    let newChan = r.get.channels.getOrDefault(cid)
    check newChan.tipMessage == opId(op)
    check newChan.tipMessage != prevTip
    check newChan.tipSlot == 2'u64

  test "wrong parent → InvalidParent":
    let
      rng = HmacDrbgContext.new()
      kp = mkEdKeyPair(rng)
      cid = mkChannelId(4)
      seedOp = ChannelInscribePayload(
        channelId: cid, inscription: @[byte 0x61],
        parent: default(Hash32), signer: kp.pubkey,
      )
      seedMantle = MantleState.init().tryApplyChannelInscribe(
        seedOp, blockSlot = 1'u64,
      ).get
      op = ChannelInscribePayload(
        channelId: cid, inscription: @[byte 0x62],
        parent: mkTxHash(seed = 0xFF), signer: kp.pubkey,
      )
      r = seedMantle.tryApplyChannelInscribe(op, blockSlot = 2'u64)
    check r.error == InvalidParent

  test "wrong signer (not in accreditedKeys) → UnauthorizedSigner":
    let
      rng = HmacDrbgContext.new()
      kp = mkEdKeyPair(rng)
      other = mkEdKeyPair(rng)
      cid = mkChannelId(5)
      seedOp = ChannelInscribePayload(
        channelId: cid, inscription: @[byte 0x61],
        parent: default(Hash32), signer: kp.pubkey,
      )
      seedMantle = MantleState.init().tryApplyChannelInscribe(
        seedOp, blockSlot = 1'u64,
      ).get
      chan = seedMantle.channels.getOrDefault(cid)
      op = ChannelInscribePayload(
        channelId: cid, inscription: @[byte 0x62],
        parent: chan.tipMessage, signer: other.pubkey,
      )
      r = seedMantle.tryApplyChannelInscribe(op, blockSlot = 2'u64)
    check r.error == UnauthorizedSigner

{.pop.}
