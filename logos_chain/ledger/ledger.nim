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
    pol_verifier, epoch_state,
  ],
  ./sdp/[registry, ops],
  ../core/mantle/[tx_types, tx_hashing, operations, proofs],
  ../core/types

from ../core/crypto/types import ZkPublicKey
export types, cryptarchia_state, channel_state, mantle_state, epoch_state, registry

type
  LedgerState* = object
    cryptarchiaLedger*: CryptarchiaState
    sdp*: SdpRegistry
    mantleLedger*: MantleState
    epochs*: EpochTracker

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
      mantleLedger: MantleState.init())
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
      mantleLedger: MantleState.init())
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
          s.sdp.state.lockedNotes, op.payload.transfer)
        s.cryptarchiaLedger = r.state
      of ChannelInscribe:
        # Envelope validity (null channel, root parent, zero signer) is
        # enforced at the chain layer when the ceremony is decoded.
        s.mantleLedger.channels = applyChannelInscribe(
          s.mantleLedger.channels, op.payload.channelInscribe, 0)
      of SdpDeclare:
        ?applySdpDeclare(s.sdp, op.payload.sdpDeclare, genesisEpoch)
      else:
        return err(UnsupportedOp)
  s.epochs = ?genesisEpochTracker(
    nonce, s.cryptarchiaLedger.latestUtxos.root, max(total, 1), cfg)
  # Epochs 0 and 1 read the registry snapshot taken at genesis:
  # https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/bedrock-service-declaration-protocol.md#snapshots
  onEpochStarted(s.sdp, genesisEpoch)
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
    # SDP epoch finalization is part of applying the first block of the new
    # epoch; reward distribution slots in ahead of the withdrawal removal
    # once it lands.
    # https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md#sdp-epoch-finalization
    onEpochStarted(s.sdp, s.epochs.activeEpoch.epoch)
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
  let entropy = frFromBytesLE(proof.entropyContribution).valueOr:
    return err(InvalidProof)
  s.epochs = s.epochs.recordBlock(slot, entropy)
  ok(s)

proc tryApplyTx*(
    state: sink LedgerState,
    tx: SignedMantleTx,
    epoch: EpochNumber,
    slot: SlotNumber,
): Result[tuple[state: LedgerState, balance: Balance], LedgerError] =
  ## Applies one transaction. Returns the new state and Transfer-only
  ## balance delta. `slot` is used by channel ops for sequencer rotation.
  if tx.tx.ops.len != tx.opProofs.len:
    return err(InvalidProof)

  var
    s = state
    balance = Balance.zero
  let txHash = mantleTxHash(tx.tx)
  for i in 0 ..< tx.tx.ops.len:
    let
      op = tx.tx.ops[i]
      proof = tx.opProofs[i]
    case op.payload.kind
    of Transfer:
      if proof.kind != opfTransfer:
        return err(InvalidProof)
      let r =
        ?s.cryptarchiaLedger.tryApplyTransfer(
          s.sdp.state.lockedNotes,
          op.payload.transfer, proof.transferProof, txHash,
        )
      s.cryptarchiaLedger = r.state
      balance = ?balance.checkedAdd(r.balance)
    of SdpDeclare:
      if proof.kind != opfSdpDeclare:
        return err(InvalidProof)
      ?tryApplySdpDeclare(
        s.sdp,
        op.payload.sdpDeclare,
        proof.declarationProof,
        txHash,
        s.cryptarchiaLedger.latestUtxos,
        epoch,
      )
    of SdpWithdraw:
      if proof.kind != opfSdpWithdraw:
        return err(InvalidProof)
      ?tryApplySdpWithdraw(
        s.sdp,
        op.payload.sdpWithdraw,
        proof.sdpWithdrawProof,
        txHash,
        s.cryptarchiaLedger.latestUtxos,
        epoch,
      )
    of SdpActive:
      if proof.kind != opfSdpActive:
        return err(InvalidProof)
      ?tryApplySdpActive(
        s.sdp,
        op.payload.sdpActive,
        proof.sdpActiveProof,
        txHash,
        epoch,
      )
    of ChannelInscribe:
      if proof.kind != opfChannelInscribe:
        return err(InvalidProof)
      s.mantleLedger = ?s.mantleLedger.tryApplyChannelInscribe(
        op.payload.channelInscribe, proof.ed25519SigProof, txHash, slot,
      )
    of ChannelConfig:
      if proof.kind != opfChannelConfig:
        return err(InvalidProof)
      s.mantleLedger = ?s.mantleLedger.tryApplyChannelConfig(
        op.payload.channelConfig, proof.channelConfigOpProof, txHash, slot,
      )
    of ChannelDeposit:
      if proof.kind != opfChannelDeposit:
        return err(InvalidProof)
      let r = ?s.mantleLedger.tryApplyChannelDeposit(
        s.cryptarchiaLedger, s.sdp.state.lockedNotes,
        op.payload.channelDeposit, proof.channelDepositProof, txHash,
      )
      # Field-wise update: a whole-object constructor would reset omitted fields.
      s.cryptarchiaLedger = r.cs
      s.mantleLedger = r.ms
    of ChannelWithdraw:
      if proof.kind != opfChannelWithdraw:
        return err(InvalidProof)
      let r = ?s.mantleLedger.tryApplyChannelWithdraw(
        s.cryptarchiaLedger,
        op.payload.channelWithdraw, proof.channelWithdrawOpProof, txHash,
      )
      s.cryptarchiaLedger = r.cs
      s.mantleLedger = r.ms
    else:
      return err(UnsupportedOp)
  ok((state: s, balance: balance))

proc tryApplyTxns*(
    state: sink LedgerState,
    txs: openArray[SignedMantleTx],
    slot: SlotNumber,
): Result[LedgerState, LedgerError] =
  ## Applies a block's transactions in order under the state's active epoch;
  ## each tx must net to zero balance.
  var s = state
  # The state, not the caller, is the source of truth for the epoch.
  let epoch = s.epochs.activeEpoch.epoch
  for tx in txs:
    let r = ?s.tryApplyTx(tx, epoch, slot)
    s = r.state
    if r.balance > Balance.zero:
      return err(UnbalancedTransaction)
    if r.balance < Balance.zero:
      return err(InsufficientBalance)
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
  ## Caller invokes `commitUpdate` to install the result and run SDP
  ## epoch-boundary updates, or drops it to reject.
  if parentId notin l.states:
    return err(ParentNotFound)
  let
    parent = l.states.getOrDefault(parentId)
    afterHeader = ?parent.tryApplyHeader(slot, proof, l.config, l.leaderProofVerifier)
    afterTxs = ?afterHeader.tryApplyTxns(txs, slot)
  ok((id: id, state: afterTxs))

{.pop.}
