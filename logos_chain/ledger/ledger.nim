# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Composite `LedgerState` (cryptarchia + mantle sub-states) and the
## chain-wide `Ledger[Id]` state-by-block-id map.

{.push raises: [], gcsafe.}

import
  results,
  std/tables,
  ./[
    balance, types, cryptarchia_state, channel_state, mantle_state,
    pol_verifier, epoch_state, fee_market, block_rewards,
  ],
  ./sdp/[registry, ops],
  ../core/mantle/[tx_types, tx_hashing, operations, proofs, gas],
  ../core/types

from ../core/crypto/types import ZkPublicKey
export
  types, cryptarchia_state, channel_state, mantle_state, epoch_state, registry,
  fee_market, block_rewards, gas

type
  LedgerState* = object
    cryptarchiaLedger*: CryptarchiaState
    sdp*: SdpRegistry
    mantleLedger*: MantleState
    epochs*: EpochTracker
    feeMarket*: FeeMarket
    blockNumber*: uint64 ## applied-block count; genesis state = 0
    feeWindow*: FeeWindow

  Ledger*[Id] = object
    states: Table[Id, LedgerState]
    config: LedgerConfig
    leaderProofVerifier: LeaderProofVerifier

func latestUtxos*(s: LedgerState): lent UtxoStore =
  ## The live UTXO set.
  s.cryptarchiaLedger.latestUtxos

func stakeContribution(
    value: uint64, pk: ZkPublicKey, faucetPk: Opt[ZkPublicKey]): uint64 =
  ## A note's contribution to total stake — zero for the faucet note, whose
  ## outsized mint would dominate the lottery.
  if faucetPk.isSome and pk == faucetPk.get: 0'u64 else: value

func fromUtxos*(
    _: typedesc[LedgerState],
    utxos: openArray[Utxo],
    nonce: FieldElement,
    sdp: sink SdpRegistry,
    cfg: LedgerConfig,
): Result[LedgerState, LedgerError] =
  ## Genesis-style state seeded with epoch bookkeeping from the UTXO set;
  ## total stake is the faucet-filtered note sum, floored at 1.
  var
    s = LedgerState(
      cryptarchiaLedger: CryptarchiaState.init(utxos),
      sdp: sdp,
      mantleLedger: MantleState.init(),
      feeMarket: FeeMarket.init())
    total = 0'u64
  for u in utxos:
    let c = stakeContribution(u.note.value, u.note.zkPublicKey, cfg.faucetPk)
    doAssert total <= uint64.high - c, "total stake overflows uint64"
    total += c
  s.epochs = ?genesisEpochTracker(
    nonce, s.cryptarchiaLedger.latestUtxos.root, max(total, 1), cfg)
  ok(s)

proc fromGenesis*(
    _: typedesc[LedgerState],
    genesisTxs: openArray[SignedMantleTx],
    nonce: FieldElement,
    sdp: sink SdpRegistry,
    cfg: LedgerConfig,
): Result[LedgerState, LedgerError] =
  ## Genesis state from the genesis block's transactions: ops run through the
  ## pure transition cores (no proof or balance checks), then epochs are
  ## seeded from the faucet-filtered stake and ceremony nonce.
  const genesisEpoch = 0'u64
  var
    s = LedgerState(
      cryptarchiaLedger: CryptarchiaState.init(),
      sdp: sdp,
      mantleLedger: MantleState.init(),
      feeMarket: FeeMarket.init())
    total = 0'u64
  for tx in genesisTxs:
    for op in tx.tx.ops:
      case op.payload.kind
      of Transfer:
        if op.payload.transfer.inputs.noteIds.len > 0:
          return err(InputInGenesis)
        for note in op.payload.transfer.outputs.notes:
          let c = stakeContribution(note.value, note.zkPublicKey, cfg.faucetPk)
          doAssert total <= uint64.high - c, "total stake overflows uint64"
          total += c
        let r = ?s.cryptarchiaLedger.applyTransferState(
          s.sdp.state.lockedNotes, s.mantleLedger.channelNotes,
          op.payload.transfer)
        s.cryptarchiaLedger = r.state
      of ChannelInscribe:
        # Envelope validity (null channel, root parent, zero signer) is
        # enforced at the chain layer when the ceremony is decoded.
        s.mantleLedger.channels = applyChannelInscribe(
          s.mantleLedger.channels, op.payload.channelInscribe, 0)
      of SdpDeclare:
        # Genesis skips op validation. The rewards provider snapshot will
        # key providers by provider_id and hash zk_id leaves. A duplicate
        # of either corrupts it. Reject the ceremony input at load.
        ?validateServiceScopedUniqueness(op.payload.sdpDeclare, s.sdp.state)
        s.sdp = ?applySdpDeclare(s.sdp, op.payload.sdpDeclare, genesisEpoch)
      else:
        return err(UnsupportedOp)
  s.epochs = ?genesisEpochTracker(
    nonce, s.cryptarchiaLedger.latestUtxos.root, max(total, 1), cfg)
  # Epochs 0 and 1 read the registry snapshot taken at genesis:
  # https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/bedrock-service-declaration-protocol.md#snapshots
  s.sdp = onEpochStarted(s.sdp, genesisEpoch)
  ok(s)

proc tryApplyHeader*(
    state: sink LedgerState,
    slot: SlotNumber,
    proof: ProofOfLeadership,
    cfg: LedgerConfig,
    verifyProof: LeaderProofVerifier = verifyLeaderProof,
): Result[LedgerState, LedgerError] =
  ## Epoch pipeline for `slot`, leader-proof verification against the active
  ## epoch state, then entropy/density bookkeeping.
  var s = state
  let prevEpoch = s.epochs.activeEpoch.epoch
  s.epochs = ?s.epochs.advanceEpochs(
    slot, s.cryptarchiaLedger.latestUtxos.root, cfg)
  if s.epochs.activeEpoch.epoch > prevEpoch:
    # Storage-market update runs once per crossed epoch: the first iteration
    # consumes the finished epoch's usage counter, later iterations (skipped
    # empty epochs) run with a zero counter, per the per-epoch timeframe.
    for _ in prevEpoch ..< s.epochs.activeEpoch.epoch:
      s.feeMarket = s.feeMarket.updateStorageMarket()
    # SDP epoch finalization is part of applying the first block of the new
    # epoch; reward distribution slots in ahead of the withdrawal removal
    # once it lands.
    # https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md#sdp-epoch-finalization
    s.sdp = onEpochStarted(s.sdp, s.epochs.activeEpoch.epoch)
    s.cryptarchiaLedger.leader = ?s.cryptarchiaLedger.leader.addEpochVouchers()
  let
    active = s.epochs.activeEpoch
    public = LeaderPublic(
      slot: slot,
      epochNonce: active.nonce,
      lottery0: active.lottery0,
      lottery1: active.lottery1,
      agedRoot: active.agedUtxoRoot,
      latestRoot: s.cryptarchiaLedger.latestUtxos.root)
    verified = verifyProof(proof, public).valueOr:
      return err(VerifierNotInitialised)
  if not verified:
    return err(InvalidProof)

  s.cryptarchiaLedger.leader =
    s.cryptarchiaLedger.leader.recordBlockLeader(proof.leaderVoucher)

  let entropy = frFromBytesLE(proof.entropyContribution).valueOr:
    return err(InvalidProof)
  s.epochs = s.epochs.recordBlock(slot, entropy)
  ok(s)

func multisigThreshold(s: LedgerState, op: Op): uint16 =
  ## Signature count the ledger will verify for a channel multisig op —
  ## the channel's threshold as of the pre-op state, 0 when absent.
  case op.payload.kind
  of ChannelConfig:
    let ch = s.mantleLedger.channels.get(op.payload.channelConfig.channel).valueOr:
      return 0'u16
    ch.configurationThreshold
  of ChannelWithdraw:
    let ch = s.mantleLedger.channels.get(op.payload.channelWithdraw.channel).valueOr:
      return 0'u16
    ch.transferThreshold
  of ChannelTransfer:
    let ch = s.mantleLedger.channels.get(op.payload.channelTransfer.channel).valueOr:
      return 0'u16
    ch.transferThreshold
  else:
    0'u16

proc tryApplyTx*(
    state: sink LedgerState,
    tx: SignedMantleTx,
    epoch: EpochNumber,
    slot: SlotNumber,
): Result[tuple[state: LedgerState, balance: Balance, executionGas: Gas], LedgerError] =
  ## Applies one transaction; the returned balance is the Transfer-only
  ## delta. `slot` is used by channel ops for sequencer rotation.
  if tx.tx.ops.len != tx.opProofs.len:
    return err(InvalidProof)

  var
    s = state
    balance = Balance.zero
    txExecutionGas = Gas(0)
  let txHash = mantleTxHash(tx.tx)
  for i in 0 ..< tx.tx.ops.len:
    let
      op = tx.tx.ops[i]
      proof = tx.opProofs[i]
      opGas = execution_gas(op, s.multisigThreshold(op))
    txExecutionGas = txExecutionGas.checkedAdd(opGas).valueOr:
      return err(GasOverflow)
    if proof.kind != expectedOpProofKindForOpcode(op.opcode):
      return err(InvalidProof)
    case op.payload.kind
    of Transfer:
      let r =
        ?s.cryptarchiaLedger.tryApplyTransfer(
          s.sdp.state.lockedNotes, s.mantleLedger.channelNotes,
          op.payload.transfer, proof.transferProof, txHash,
        )
      s.cryptarchiaLedger = r.state
      balance = ?balance.checkedAdd(r.balance)
    of SdpDeclare:
      s.sdp = ?tryApplySdpDeclare(
        s.sdp,
        op.payload.sdpDeclare,
        proof.declarationProof,
        txHash,
        s.cryptarchiaLedger.latestUtxos,
        s.mantleLedger.channelNotes,
        epoch,
      )
    of SdpWithdraw:
      s.sdp = ?tryApplySdpWithdraw(
        s.sdp,
        op.payload.sdpWithdraw,
        proof.sdpWithdrawProof,
        txHash,
        s.cryptarchiaLedger.latestUtxos,
        epoch,
      )
    of SdpActive:
      s.sdp = ?tryApplySdpActive(
        s.sdp,
        op.payload.sdpActive,
        proof.sdpActiveProof,
        txHash,
        epoch,
      )
    of ChannelInscribe:
      s.mantleLedger = ?s.mantleLedger.tryApplyChannelInscribe(
        op.payload.channelInscribe, proof.ed25519SigProof, txHash, slot,
      )
    of ChannelConfig:
      s.mantleLedger = ?s.mantleLedger.tryApplyChannelConfig(
        op.payload.channelConfig, proof.channelConfigOpProof, txHash, slot,
      )
    of ChannelDeposit:
      let r = ?s.mantleLedger.tryApplyChannelDeposit(
        s.cryptarchiaLedger, s.sdp.state.lockedNotes,
        op.payload.channelDeposit, proof.channelDepositProof, txHash,
      )
      # Field-wise update: a whole-object constructor would reset omitted fields.
      s.cryptarchiaLedger = r.cs
      s.mantleLedger = r.ms
    of ChannelWithdraw:
      s.mantleLedger = ?s.mantleLedger.tryApplyChannelWithdraw(
        s.cryptarchiaLedger, s.sdp.state.lockedNotes,
        op.payload.channelWithdraw, proof.channelWithdrawOpProof, txHash,
      )
    of ChannelTransfer:
      let r = ?s.mantleLedger.tryApplyChannelTransfer(
        s.cryptarchiaLedger, s.sdp.state.lockedNotes,
        op.payload.channelTransfer, proof.channelTransferOpProof, txHash,
      )
      s.cryptarchiaLedger = r.cs
      s.mantleLedger = r.ms
    of LeaderClaim:
      s.cryptarchiaLedger = ?s.cryptarchiaLedger.tryApplyLeaderClaim(
        op.payload.leaderClaim, proof.proofOfClaimProof, txHash,
      )
  ok((state: s, balance: balance, executionGas: txExecutionGas))

func mandatory_fees(
    executionGas, storageGas: Gas, prices: GasPrices
): Result[GasCost, LedgerError] =
  let
    executionCost = executionGas.checkedMul(prices.executionBaseFee).valueOr:
      return err(GasOverflow)
    storageCost = storageGas.checkedMul(prices.storageGasPrice).valueOr:
      return err(GasOverflow)
    total = executionCost.checkedAdd(storageCost).valueOr:
      return err(GasOverflow)
  ok(total)

func creditBlockRewards*(
    state: sink LedgerState, totalFeeBurned, totalFeeTip: GasCost
): Result[LedgerState, LedgerError] =
  ## Closes one block: records its burned fees and credits the leader pool.
  # The window write comes first: the sum the emission formula sees includes
  # this block's own burned total.
  var s = state
  s.blockNumber += 1
  s.feeWindow.update(s.blockNumber, totalFeeBurned)
  let
    # The blend share stays unassigned until service-reward distribution lands.
    (_, leaderShare) = block_reward(
      s.epochs.activeEpoch.totalStake,
      s.feeWindow.summedFees,
      totalFeeBurned)
    leaderReward = leaderShare.checkedAdd(totalFeeTip).valueOr:
      return err(GasOverflow)
  s.cryptarchiaLedger.leader =
    s.cryptarchiaLedger.leader.addPendingRewards(leaderReward)
  ok(s)

proc tryApplyTxns*(
    state: sink LedgerState,
    txs: openArray[SignedMantleTx],
    slot: SlotNumber,
): Result[LedgerState, LedgerError] =
  ## Applies a block's transactions in order under the state's active epoch;
  ## each tx's transfer surplus must cover its total gas cost.
  var
    s = state
    blockExecutionGas = Gas(0)
    totalFeeBurned = GasCost(0)
    totalFeeTip = GasCost(0)
  # The state, not the caller, is the source of truth for the epoch.
  let
    epoch = s.epochs.activeEpoch.epoch
    prices = s.feeMarket.gasPrices
  for tx in txs:
    let
      r = ?s.tryApplyTx(tx, epoch, slot)
      storageGas = Gas(encodeSignedMantleTx(tx).len)
      totalCost = ?mandatory_fees(r.executionGas, storageGas, prices)
    s = r.state
    if not r.balance.covers(totalCost):
      return err(InsufficientBalance)
    totalFeeBurned = totalFeeBurned.checkedAdd(totalCost).valueOr:
      return err(GasOverflow)
    # tx_priority_tip = checked_uint64(tx_balance - tx_mandatory_fee): only
    # the difference is narrowed — a wide balance with a small tip stays valid.
    let tip = ?checked_uint64(?r.balance.checkedSub(totalCost.to(Balance)))
    totalFeeTip = totalFeeTip.checkedAdd(tip).valueOr:
      return err(GasOverflow)
    blockExecutionGas = blockExecutionGas.checkedAdd(r.executionGas).valueOr:
      return err(GasOverflow)
    if blockExecutionGas > MAX_EXECUTION_GAS_PER_BLOCK:
      return err(TooMuchExecutionGas)
    # Per-epoch usage counter driving the storage market (spec C_usage).
    s.feeMarket.storageGasConsumedInEpoch =
      s.feeMarket.storageGasConsumedInEpoch.checkedAdd(storageGas).valueOr:
        return err(GasOverflow)
  s = ?s.creditBlockRewards(totalFeeBurned, totalFeeTip)
  s.feeMarket = s.feeMarket.updateExecutionMarket(blockExecutionGas)
  ok(s)

func init*[Id](
    _: typedesc[Ledger[Id]],
    id: Id,
    state: LedgerState,
    config: LedgerConfig = LedgerConfig(),
    leaderProofVerifier: LeaderProofVerifier = verifyLeaderProof,
): Ledger[Id] =
  ## Constructs a Ledger seeded with one `(id, state)` entry.
  var states = initTable[Id, LedgerState]()
  states[id] = state
  Ledger[Id](
    states: states,
    config: config,
    leaderProofVerifier: leaderProofVerifier,
  )

func state*[Id](l: Ledger[Id], id: Id): Opt[LedgerState] =
  # `Table.[]` raises KeyError; `getOrDefault` doesn't. Two lookups, but
  # this is a cold-path API.
  if id in l.states:
    Opt.some(l.states.getOrDefault(id))
  else:
    Opt.none(LedgerState)

func config*[Id](l: Ledger[Id]): lent LedgerConfig =
  l.config

func commitUpdate*[Id](
    l: var Ledger[Id],
    id: Id,
    state: sink LedgerState,
) =
  ## Installs ``state`` at ``id``. Epoch-boundary effects were already
  ## applied by `tryApplyHeader` when the state was prepared.
  l.states[id] = state

func pruneStateAt*[Id](l: var Ledger[Id], id: Id): bool =
  if id in l.states:
    l.states.del(id)
    true
  else:
    false

proc prepareUpdate*[Id](
    l: Ledger[Id],
    id, parentId: Id,
    slot: SlotNumber,
    proof: ProofOfLeadership,
    txs: openArray[SignedMantleTx],
): Result[tuple[id: Id, state: LedgerState], LedgerError] =
  ## Validates a block's header + transactions against the parent state.
  ## Caller invokes `commitUpdate` to install the result, or drops it to reject.
  if parentId notin l.states:
    return err(ParentNotFound)
  let
    parent = l.states.getOrDefault(parentId)
    afterHeader = ?parent.tryApplyHeader(slot, proof, l.config, l.leaderProofVerifier)
    afterTxs = ?afterHeader.tryApplyTxns(txs, slot)
  ok((id: id, state: afterTxs))

{.pop.}
