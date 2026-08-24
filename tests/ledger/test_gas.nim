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
  bearssl/rand,
  libp2p/crypto/ed25519/ed25519,
  ../../logos_chain/ledger/[balance, ledger],
  ../../logos_chain/core/mantle/[tx_types, tx_hashing],
  ../../logos_chain/core/types,
  ../zk/zksign_helpers,
  ./sdp/test_helpers,
  ../core/mantle/test_helpers

from ./test_helpers import testLedgerConfig

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  zksignFixtureDir = testsDir / "../fixtures/zksign"
  zksignFixtureVk = zksignFixtureDir / "verification_key.json"
  transferProofPath = zksignFixtureDir / "proof.json"

func sentinelProof(): ProofOfLeadership =
  # All-default fields form the genesis sentinel, which bypasses leader-proof
  # verification — lets these tests drive the epoch pipeline without a VK.
  ProofOfLeadership()

proc mkState(utxos: openArray[Utxo]): LedgerState =
  LedgerState.fromUtxos(
    utxos, default(FieldElement), testSdpRegistry(), testLedgerConfig
  ).expect("seed")

proc mkFixtureTransferTx(input: Utxo): SignedMantleTx =
  ## The exact tx shape the committed zksign fixture proof was generated for
  ## (input pk mkRealZkPubKey(1), value 100; one output of value 100).
  var tx = mkTransferTx(
    [input.id], [Note(value: 100, zkPublicKey: default(ZkPublicKey))])
  tx.opProofs[0].transferProof = loadProof(transferProofPath)
  tx

proc mkInscribeTx(
    rng: ref HmacDrbgContext, channel: ChannelId
): SignedMantleTx =
  ## A single ChannelInscribe op that JIT-creates `channel`; signed with a
  ## fresh Ed25519 key over the real tx hash so it verifies in `tryApplyTx`.
  let
    kp = mkEdKeyPair(rng)
    op = createChannelInscribeOp(ChannelInscribePayload(
      channelId: channel,
      inscription: @[byte 0x01],
      parent: default(Hash32),
      signer: kp.pubkey))
    body = MantleTx(ops: @[op])
    txHash = mantleTxHash(body)
  SignedMantleTx(
    tx: body,
    opProofs: @[OpProof(
      kind: opfChannelInscribe, ed25519SigProof: sign(kp.seckey, txHash))])

suite "gas: per-operation execution gas":
  test "each op kind against its Gas Determination constant":
    check:
      execution_gas(defaultOpForOpcode(OpTransfer), 0) == Gas(590)
      execution_gas(defaultOpForOpcode(OpChannelInscribe), 0) == Gas(56)
      execution_gas(defaultOpForOpcode(OpChannelConfig), 1) == Gas(56)
      execution_gas(defaultOpForOpcode(OpChannelDeposit), 0) == Gas(590)
      execution_gas(defaultOpForOpcode(OpChannelWithdraw), 1) == Gas(56)
      execution_gas(defaultOpForOpcode(OpChannelTransfer), 1) == Gas(56)
      execution_gas(defaultOpForOpcode(OpSdpDeclare), 0) == Gas(646)
      execution_gas(defaultOpForOpcode(OpSdpWithdraw), 0) == Gas(590)
      execution_gas(defaultOpForOpcode(OpSdpActive), 0) == Gas(590)
      execution_gas(defaultOpForOpcode(OpLeaderClaim), 0) == Gas(580)

  test "channel config/withdraw/transfer scale with the multisig threshold":
    let
      cfg = defaultOpForOpcode(OpChannelConfig)
      wdr = defaultOpForOpcode(OpChannelWithdraw)
      trf = defaultOpForOpcode(OpChannelTransfer)
    check:
      execution_gas(cfg, 0) == Gas(0)
      execution_gas(cfg, 1) == Gas(56)
      execution_gas(cfg, 3) == Gas(168)
      execution_gas(cfg, uint16.high) == Gas(3_669_960)
      execution_gas(wdr, 0) == Gas(0)
      execution_gas(wdr, 1) == Gas(56)
      execution_gas(wdr, 3) == Gas(168)
      execution_gas(wdr, uint16.high) == Gas(3_669_960)
      execution_gas(trf, 0) == Gas(0)
      execution_gas(trf, 1) == Gas(56)
      execution_gas(trf, 3) == Gas(168)
      execution_gas(trf, uint16.high) == Gas(3_669_960)

  test "withdraw and transfer bill against transferThreshold, 0 when absent":
    let
      rng = HmacDrbgContext.new()
      kp = mkEdKeyPair(rng)
      cid = mkChannelId(0x41)
      configured = MantleState.init().tryApplyChannelConfig(
        ChannelConfigPayload(
          channel: cid,
          keys: @[kp.pubkey],
          configurationThreshold: 1,
          transferThreshold: 3,
        ),
        ChannelMultiSigProof(), default(Hash32), blockSlot = 0'u64,
      ).expect("valid config")
      chan = configured.channels.getOrDefault(cid)
    check chan.transferThreshold == 3
    check execution_gas(
      createChannelWithdrawOp(
        ChannelWithdrawPayload(channel: cid, inputs: @[])),
      chan.transferThreshold) == Gas(168)
    check execution_gas(
      createChannelTransferOp(
        ChannelTransferPayload(channel: cid, inputs: @[], outputs: @[])),
      chan.transferThreshold) == Gas(168)
    # A channel that doesn't exist yet bills a zero multiplier — the same
    # just-in-time path a first ChannelConfig takes.
    let absent = MantleState.init().channels.getOrDefault(mkChannelId(0x42))
    check absent.transferThreshold == 0
    check execution_gas(
      createChannelTransferOp(
        ChannelTransferPayload(channel: cid, inputs: @[], outputs: @[])),
      absent.transferThreshold) == Gas(0)

suite "gas: fee-market genesis state":
  test "FeeMarket.init opens both markets at price 1, counters at 0":
    let m = FeeMarket.init()
    check:
      m.executionBaseFee == GasPrice(1)
      m.storageGasPrice == GasPrice(1)
      m.averageExecutionGas == Gas(0)
      m.storageGasEma == Gas(0)
      m.storageGasConsumedInEpoch == Gas(0)
      m.gasPrices.executionBaseFee == GasPrice(1)
      m.gasPrices.storageGasPrice == GasPrice(1)

suite "gas: execution market update":
  test "sub-target block cannot push the base fee below 1":
    check:
      update_g_avg(0, 590) == Gas(59)
      update_base_fee(1, 59) == GasPrice(1)
    let m = FeeMarket(averageExecutionGas: 0, executionBaseFee: 1)
      .updateExecutionMarket(590)
    check:
      m.averageExecutionGas == Gas(59)
      m.executionBaseFee == GasPrice(1)

  test "an idle run of blocks holds the base fee at its floor":
    # Upward rounding keeps the market alive: without it the first sub-target
    # block would floor the genesis fee to an absorbing 0.
    var m = FeeMarket.init()
    for _ in 0 ..< 100:
      m = m.updateExecutionMarket(0)
    check:
      m.averageExecutionGas == Gas(0)
      m.executionBaseFee == GasPrice(1)

  test "sustained full blocks raise the base fee off its floor":
    var m = FeeMarket.init()
    for _ in 0 ..< 100:
      m = m.updateExecutionMarket(MAX_EXECUTION_GAS_PER_BLOCK)
    check m.executionBaseFee > GasPrice(1)

  test "at-target block holds the base fee near its previous value":
    check:
      update_g_avg(0, 3_193_460) == Gas(319_346)
      update_base_fee(1000, 319_346) == GasPrice(900)
    let m = FeeMarket(averageExecutionGas: 0, executionBaseFee: 1000)
      .updateExecutionMarket(3_193_460)
    check:
      m.averageExecutionGas == Gas(319_346)
      m.executionBaseFee == GasPrice(900)

  test "zero base fee is absorbing":
    check update_base_fee(0, 12_345) == GasPrice(0)
    let m = FeeMarket(averageExecutionGas: 500, executionBaseFee: 0)
      .updateExecutionMarket(1000)
    check m.executionBaseFee == GasPrice(0)

suite "gas: storage market update":
  test "zero usage holds the price (hold guard)":
    check:
      update_usage(0, 0) == Gas(0)
      update_storage_price(7, 0, 0) == GasPrice(7)

  test "high consumption clamps the price up":
    check:
      update_usage(1000, 0) == Gas(500)
      update_storage_price(1000, 1000, 500) == GasPrice(1125)

  test "zero consumption clamps the price down":
    check:
      update_usage(0, 1000) == Gas(500)
      update_storage_price(1000, 0, 500) == GasPrice(875)

  test "mid-range consumption tracks the ratio":
    check:
      update_usage(600, 500) == Gas(550)
      update_storage_price(1000, 600, 550) == GasPrice(1091) # ceil(600000/550)

  test "the genesis price is a floor that heavy usage can still leave":
    check:
      update_storage_price(1, 0, 500) == GasPrice(1) # ceil(7/8), not 0
      update_storage_price(1, 1000, 500) == GasPrice(2) # ceil(9/8), not 1

  test "updateStorageMarket consumes and resets the epoch counter":
    let m = FeeMarket(
      storageGasEma: 500, storageGasPrice: 1000, storageGasConsumedInEpoch: 600)
      .updateStorageMarket()
    check:
      m.storageGasEma == Gas(550)
      m.storageGasPrice == GasPrice(1091)
      m.storageGasConsumedInEpoch == Gas(0)

  test "hold-guard sanity pair":
    # Zero effective target with nonzero prior usage still clamps down; zero
    # usage holds.
    let held = FeeMarket(
      storageGasEma: 0, storageGasPrice: 1000, storageGasConsumedInEpoch: 0)
      .updateStorageMarket()
    check:
      held.storageGasEma == Gas(0)
      held.storageGasPrice == GasPrice(1000)
    let clamped = FeeMarket(
      storageGasEma: 800, storageGasPrice: 1000, storageGasConsumedInEpoch: 0)
      .updateStorageMarket()
    check:
      clamped.storageGasEma == Gas(400)
      clamped.storageGasPrice == GasPrice(875)

suite "gas: tx execution gas and block limit":
  test "tryApplyTx sums per-op execution gas over the tx":
    # Two transfer ops would sum to 1180; driven here with Ed25519-signable
    # channel-inscribe ops (56 each), since transfers need a prover fixture.
    let transferOp = defaultOpForOpcode(OpTransfer)
    check execution_gas(transferOp, 0) + execution_gas(transferOp, 0) == Gas(1180)

    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      op1 = createChannelInscribeOp(ChannelInscribePayload(
        channelId: mkChannelId(1), inscription: @[byte 0x01],
        parent: default(Hash32), signer: kp1.pubkey))
      op2 = createChannelInscribeOp(ChannelInscribePayload(
        channelId: mkChannelId(2), inscription: @[byte 0x02],
        parent: default(Hash32), signer: kp2.pubkey))
      body = MantleTx(ops: @[op1, op2])
      txHash = mantleTxHash(body)
      tx = SignedMantleTx(
        tx: body,
        opProofs: @[
          OpProof(kind: opfChannelInscribe, ed25519SigProof: sign(kp1.seckey, txHash)),
          OpProof(kind: opfChannelInscribe, ed25519SigProof: sign(kp2.seckey, txHash)),
        ],
      )
    var s = mkState(@[])
    let r = s.tryApplyTx(tx, epoch = 0'u64, slot = 0'u64)
    check r.isOk
    let mf = s.mandatory_fees(tx)
    check mf.isOk
    check mf.get.executionGas == Gas(112)

  test "per-block execution gas limit constant and accumulator overflow":
    # The TooMuchExecutionGas branch fires when the block's summed execution
    # gas exceeds MAX_EXECUTION_GAS_PER_BLOCK; tripping it end-to-end needs
    # ~57k verified ops, so the arithmetic path is exercised directly here.
    check MAX_EXECUTION_GAS_PER_BLOCK == Gas(3_193_460)
    check checkedAdd(MAX_EXECUTION_GAS_PER_BLOCK, 1'u64).isSome
    check checkedAdd(uint64.high, 1'u64).isNone
    check checkedMul(1000'u64, 1000'u64).isSome
    check checkedMul(uint64.high, 2'u64).isNone

suite "gas: fee enforcement via committed transfer fixture":
  setup:
    check installZksignVk(zksignFixtureVk)

  test "balanced transfer accepted only when total gas cost is zero":
    let input = mkUtxoWithPk(mkRealZkPubKey(1), value = 100)
    var accept = mkState([input])
    accept.feeMarket.executionBaseFee = 0
    accept.feeMarket.storageGasPrice = 0
    check accept.tryApplyTxns([mkFixtureTransferTx(input)], slot = 0'u64).isOk

    var reject = mkState([input])
    reject.feeMarket.executionBaseFee = 0
    reject.feeMarket.storageGasPrice = 1 # storage cost > zero surplus
    let r = reject.tryApplyTxns([mkFixtureTransferTx(input)], slot = 0'u64)
    check r.error == InsufficientBalance

  test "prices come from ledger state, not the transaction":
    # The same tx is accepted at zeroed prices and rejected once the state's
    # execution base fee is raised — nothing the tx carries changed.
    let input = mkUtxoWithPk(mkRealZkPubKey(1), value = 100)
    var sOk = mkState([input])
    sOk.feeMarket.executionBaseFee = 0
    sOk.feeMarket.storageGasPrice = 0
    check sOk.tryApplyTxns([mkFixtureTransferTx(input)], slot = 0'u64).isOk

    var sBad = mkState([input])
    sBad.feeMarket.executionBaseFee = 10
    sBad.feeMarket.storageGasPrice = 0
    let r = sBad.tryApplyTxns([mkFixtureTransferTx(input)], slot = 0'u64)
    check r.error == InsufficientBalance

suite "gas: fee comparison width":
  test "surpluses at and past uint64 cover their fees":
    let
      one = 1'u64.to(Balance)
      u64Max = uint64.high.to(Balance)
    check:
      Balance.zero.covers(0'u64)
      not Balance.zero.covers(1'u64)
      u64Max.covers(uint64.high)
      not (u64Max - one).covers(uint64.high)
      (u64Max + one).covers(1'u64) # 2^64 wraps to 0 under a uint64 narrow
      not (Balance.zero - one).covers(0'u64)

suite "gas: storage accumulation and epoch rotation":
  test "block accumulates storage gas; rotation consumes and resets it":
    let rng = HmacDrbgContext.new()
    var s = mkState(@[])
    s.feeMarket.executionBaseFee = 0
    s.feeMarket.storageGasPrice = 0
    let
      tx = mkInscribeTx(rng, mkChannelId(1))
      encodedLen = Gas(encodeSignedMantleTx(tx).len)
    s = s.tryApplyTxns([tx], slot = 1'u64).expect("applied")
    check s.feeMarket.storageGasConsumedInEpoch == encodedLen

    s = s.tryApplyHeader(100, sentinelProof(), testLedgerConfig).expect("rotation")
    check:
      s.epochs.activeEpoch.epoch == 1
      s.feeMarket.storageGasConsumedInEpoch == Gas(0)
      s.feeMarket.storageGasEma == encodedLen div 2 # update_usage(len, 0)

  test "multi-epoch skip runs the storage update once per crossed epoch":
    var s = mkState(@[])
    s = s.tryApplyHeader(5, sentinelProof(), testLedgerConfig).expect("valid")
    s.feeMarket.storageGasEma = 800 # seed a nonzero EMA to observe halving
    s = s.tryApplyHeader(350, sentinelProof(), testLedgerConfig).expect("rotation")
    check:
      s.epochs.activeEpoch.epoch == 3
      s.feeMarket.storageGasEma == Gas(100) # 800 → 400 → 200 → 100
      s.feeMarket.storageGasConsumedInEpoch == Gas(0)

  test "mandatory_fees for SignedMantleTx combines execution gas and storage gas":
    let rng = HmacDrbgContext.new()
    let tx = mkInscribeTx(rng, mkChannelId(1))
    var s = mkState(@[])
    s.feeMarket.executionBaseFee = 2
    s.feeMarket.storageGasPrice = 3
    let mf = s.mandatory_fees(tx).expect(
      "mandatory_fees should return fee breakdown (totalCost, executionGas, storageGas) for signed mantle tx"
    )
    let expectedCost = (mf.executionGas * 2) + (mf.storageGas * 3)
    check mf.totalCost == expectedCost

  test "advanceEpochAndMarket rotates storage market and advances epoch without proof":
    var s = mkState(@[])
    s.feeMarket.storageGasEma = 800
    let advanced = s.advanceEpochAndMarket(350, testLedgerConfig).expect("advanced")
    check:
      advanced.epochs.activeEpoch.epoch == 3
      advanced.feeMarket.storageGasEma == Gas(100) # 800 → 400 → 200 → 100
      advanced.feeMarket.storageGasConsumedInEpoch == Gas(0)

{.pop.}
