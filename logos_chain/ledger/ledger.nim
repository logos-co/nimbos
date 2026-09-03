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
  types, balance, cryptarchia_state, channel_state, mantle_state, epoch_state, registry,
  fee_market, block_rewards, gas, tx_types.ValidSignedMantleTx

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
    poqVerifier: PoqVerifier

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
  const genesisEpoch: EpochNumber = 0
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
        # validated statelessly in `chain/genesis.nim` (`decodeCryptarchiaParameter`).
        s.mantleLedger.channels = applyChannelInscribe(
          s.mantleLedger.channels, op.payload.channelInscribe, 0)
      of SdpDeclare:
        s.sdp = ?applySdpDeclare(s.sdp, op.payload.sdpDeclare, genesisEpoch)
      else:
        return err(UnsupportedOp)
  s.epochs = ?genesisEpochTracker(
    nonce, s.cryptarchiaLedger.latestUtxos.root, max(total, 1), cfg)
  # Epochs 0 and 1 read the registry snapshot taken at genesis:
  # https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/bedrock-service-declaration-protocol.md#snapshots
  s.sdp = onEpochStarted(s.sdp, genesisEpoch)
  ok(s)

proc advanceEpochAndMarket*(
    state: sink LedgerState,
    slot: SlotNumber,
    cfg: LedgerConfig,
): Result[LedgerState, LedgerError] =
  ## Advances epoch tracking, runs storage market updates for crossed epochs,
  ## finalizes SDP epoch transitions, and credits epoch vouchers for `slot`.
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
    s.cryptarchiaLedger.leader = ?s.cryptarchiaLedger.leader.addEpochVouchers()
    # Rewards distribute before withdrawal removal, so a withdrawn
    # provider still collects its final reward:
    # https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md#sdp-epoch-finalization
    let (blendRewards, minted) = s.sdp.blendRewards.rotateEpoch(
      prevEpoch, s.epochs.activeEpoch.epoch,
      s.sdp.activeBlendProviders(prevEpoch),
      s.epochs.activeEpoch.nonce, s.sdp.params.rewardsParams)
    s.sdp.blendRewards = blendRewards
    s.sdp = onEpochStarted(s.sdp, s.epochs.activeEpoch.epoch)
    # Reward notes enter the live UTXO set in mint order, before the
    # leader proof is checked against the latest root.
    s.cryptarchiaLedger = s.cryptarchiaLedger.insertMintedUtxos(minted)
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
  var s = ?state.advanceEpochAndMarket(slot, cfg)
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
    return err(InvalidProofOfLeadership)

  s.cryptarchiaLedger.leader =
    s.cryptarchiaLedger.leader.recordBlockLeader(proof.leaderVoucher)

  let entropy = frFromBytesLE(proof.entropyContribution).valueOr:
    return err(InvalidProofOfLeadership)
  s.epochs = s.epochs.recordBlock(slot, entropy)
  ok(s)

func opMultisigThreshold(op: Op, proof: OpProof): Result[uint16, LedgerError] =
  ## Signature count for channel multisig operations (ChannelConfig, ChannelWithdraw, ChannelTransfer).
  ##
  ## We count signatures directly from the attached proof (`proof.signatures.len`) rather
  ## than querying the ledger state. This avoids ordering issues when multiple ops in the
  ## same tx create or update a channel before using it, and charges for the signatures
  ## actually verified by `verifyChannelMultiSig` in `channel_state.nim` (L92-L107) — if
  ## `proof.signatures.len != threshold`, the transaction will not be validated (`ThresholdUnmet`).
  if proof.kind != expectedOpProofKindForOpcode(op.opcode):
    return err(InvalidTxProof)
  case op.payload.kind
  of ChannelConfig:
    ok(max(uint16(proof.channelConfigOpProof.signatures.len), 1'u16))
  of ChannelWithdraw:
    ok(max(uint16(proof.channelWithdrawOpProof.signatures.len), 1'u16))
  of ChannelTransfer:
    ok(max(uint16(proof.channelTransferOpProof.signatures.len), 1'u16))
  else:
    ok(1'u16)

proc tryApplyTx*(
    s: var LedgerState,
    tx: ValidSignedMantleTx,
    epoch: EpochNumber,
    slot: SlotNumber,
    verifyPoq: PoqVerifier,
): Result[Balance, LedgerError] =
  ## Applies one transaction in-place; the returned balance is the Transfer-only
  ## delta. `slot` is used by channel ops for sequencer rotation.
  ## Note: Structural and cryptographic validation is guaranteed at compile-time
  ## via `ValidSignedMantleTx`.
  var balance = Balance.zero
  let txHash = mantleTxHash(tx.tx)
  for i in 0 ..< tx.tx.ops.len:
    let
      op = tx.tx.ops[i]
      proof = tx.opProofs[i]
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
        verifyPoq,
      )
    of ChannelInscribe:
      s.mantleLedger = ?s.mantleLedger.tryApplyChannelInscribe(
        op.payload.channelInscribe, slot,
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
        op.payload.leaderClaim,
      )
  ok(balance)

proc txExecutionGas*(
    tx: ValidSignedMantleTx,
): Result[Gas, LedgerError] =
  var total = Gas(0)
  for i in 0 ..< tx.tx.ops.len:
    let
      op = tx.tx.ops[i]
      proof = tx.opProofs[i]
      thresh = ? opMultisigThreshold(op, proof)
    let added = checkedAdd(total, execution_gas(op, thresh)).valueOr:
      return err(GasOverflow)
    total = added
  ok(total)

func mandatory_fees*(
    s: LedgerState,
    execGas: Gas,
    txByteLen: int,
): Result[tuple[totalCost: GasCost, executionGas, storageGas: Gas], LedgerError] =
  let storageGas = Gas(txByteLen)
  let prices = s.feeMarket.gasPrices
  let executionCost = execGas.checkedMul(prices.executionBaseFee).valueOr:
    return err(GasOverflow)
  let storageCost = storageGas.checkedMul(prices.storageGasPrice).valueOr:
    return err(GasOverflow)
  let totalCost = executionCost.checkedAdd(storageCost).valueOr:
    return err(GasOverflow)
  ok((totalCost: totalCost, executionGas: execGas, storageGas: storageGas))

proc mandatory_fees*(
    s: LedgerState,
    tx: ValidSignedMantleTx,
): Result[tuple[totalCost: GasCost, executionGas, storageGas: Gas], LedgerError] =
  let execGas = ? txExecutionGas(tx)
  let txByteLen = byteLen(tx)
  s.mandatory_fees(execGas, txByteLen)

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
    (blendShare, leaderShare) = block_reward(
      s.epochs.activeEpoch.totalStake,
      s.feeWindow.summedFees,
      totalFeeBurned)
    leaderReward = leaderShare.checkedAdd(totalFeeTip).valueOr:
      return err(GasOverflow)
  s.sdp.blendRewards = ?s.sdp.blendRewards.addIncome(blendShare)
  s.cryptarchiaLedger.leader =
    s.cryptarchiaLedger.leader.addPendingRewards(leaderReward)
  ok(s)

proc tryApplyTxns*(
    state: sink LedgerState,
    txs: openArray[ValidSignedMantleTx],
    slot: SlotNumber,
    verifyPoq: PoqVerifier,
): Result[LedgerState, LedgerError] =
  ## Applies a block's transactions in order under the state's active epoch;
  ## each tx's transfer surplus must cover its total gas cost.
  var
    s = state
    blockExecutionGas = Gas(0)
    totalFeeBurned = GasCost(0)
    totalFeeTip = GasCost(0)
  # The state, not the caller, is the source of truth for the epoch.
  let epoch = s.epochs.activeEpoch.epoch
  for tx in txs:
    let
      (totalCost, execGas, storageGas) = ?s.mandatory_fees(tx)
      txBalance = ?s.tryApplyTx(tx, epoch, slot, verifyPoq)
    if not txBalance.covers(totalCost):
      return err(InsufficientBalance)
    totalFeeBurned = totalFeeBurned.checkedAdd(totalCost).valueOr:
      return err(GasOverflow)
    # tx_priority_tip = checked_uint64(tx_balance - tx_mandatory_fee): only
    # the difference is narrowed — a wide balance with a small tip stays valid.
    let tip = ?checked_uint64(?txBalance.checkedSub(totalCost.to(Balance)))
    totalFeeTip = totalFeeTip.checkedAdd(tip).valueOr:
      return err(GasOverflow)
    blockExecutionGas = blockExecutionGas.checkedAdd(execGas).valueOr:
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
    config: LedgerConfig,
    leaderProofVerifier: LeaderProofVerifier = verifyLeaderProof,
    poqVerifier: PoqVerifier = acceptAllPoq,
): Ledger[Id] =
  ## Constructs a Ledger seeded with one `(id, state)` entry.
  # TODO(zk): the default becomes the real quota verifier when the
  # circuit lands.
  var states: Table[Id, LedgerState]
  states[id] = state
  Ledger[Id](
    states: states,
    config: config,
    leaderProofVerifier: leaderProofVerifier,
    poqVerifier: poqVerifier,
  )

func state*[Id](l: Ledger[Id], id: Id): Opt[LedgerState] =
  # `Table.[]` raises KeyError; `getOrDefault` doesn't. Two lookups, but
  # this is a cold-path API.
  if id in l.states:
    Opt.some(l.states.getOrDefault(id))
  else:
    Opt.none(LedgerState)

func hasState*[Id](l: Ledger[Id], id: Id): bool {.inline.} =
  id in l.states

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
    txs: openArray[ValidSignedMantleTx],
): Result[tuple[id: Id, state: LedgerState], LedgerError] =
  ## Validates a block's header + transactions against the parent state.
  ## Caller invokes `commitUpdate` to install the result, or drops it to reject.
  if parentId notin l.states:
    return err(ParentNotFound)
  let
    parent = l.states.getOrDefault(parentId)
    afterHeader = ?parent.tryApplyHeader(slot, proof, l.config, l.leaderProofVerifier)
    afterTxs = ?afterHeader.tryApplyTxns(txs, slot, l.poqVerifier)
  ok((id: id, state: afterTxs))

{.pop.}
