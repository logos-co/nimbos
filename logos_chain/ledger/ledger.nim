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
  std/[options, tables],
  ./[
    balance, types, cryptarchia_state, channel_state, mantle_state,
    pol_verifier, leader_claim,
  ],
  ./sdp/[registry, ops],
  ../core/mantle/[tx_types, tx_hashing, operations, proofs],
  ../core/types

export types, cryptarchia_state, registry, channel_state, mantle_state, leader_claim

type
  LedgerState* = object
    cryptarchiaLedger*: CryptarchiaState
    sdp*: SdpRegistry
    mantleLedger*: MantleState

  Ledger*[Id] = object
    states: Table[Id, LedgerState]
    config: LedgerConfig

func fromUtxos*(
    _: typedesc[LedgerState],
    utxos: openArray[Utxo],
    sdp: sink SdpRegistry,
): LedgerState =
  ## Builds a genesis-style state from the given UTXO set and SDP registry.
  LedgerState(
    cryptarchiaLedger: CryptarchiaState.init(utxos),
    sdp: sdp,
    mantleLedger: MantleState.init(),
  )

func latestUtxos*(s: LedgerState): lent UtxoStore =
  ## The live UTXO set.
  s.cryptarchiaLedger.latestUtxos

proc tryApplyHeader*(
    state: sink LedgerState, slot: SlotNumber, proof: ProofOfLeadership
): Result[LedgerState, LedgerError] =
  ## Verifies the leader proof against the singleton PoL VK installed at
  ## startup. Returns `InvalidProof` on rejection, `VerifierNotInitialised`
  ## if the singleton wasn't installed.
  # Epoch-derived `LeaderPublic` fields (nonce, lottery, agedRoot) stay at
  # `default(FieldElement)` until `EpochState` lands.
  let
    public =
      LeaderPublic(slot: slot, latestRoot: state.cryptarchiaLedger.latestUtxos.root)
    verified = verifyLeaderProof(proof, public).valueOr:
      return err(VerifierNotInitialised)
  if not verified:
    return err(InvalidProof)
  ok(state)

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
      s = LedgerState(cryptarchiaLedger: r.cs, mantleLedger: r.ms, sdp: s.sdp)
    of ChannelWithdraw:
      if proof.kind != opfChannelWithdraw:
        return err(InvalidProof)
      let r = ?s.mantleLedger.tryApplyChannelWithdraw(
        s.cryptarchiaLedger,
        op.payload.channelWithdraw, proof.channelWithdrawOpProof, txHash,
      )
      s = LedgerState(cryptarchiaLedger: r.cs, mantleLedger: r.ms, sdp: s.sdp)
    of LeaderClaim:
      if proof.kind != opfLeaderClaim:
        return err(InvalidProof)
      let r =
        ?s.cryptarchiaLedger.tryApplyLeaderClaim(
          op.payload.leaderClaim, proof.proofOfClaimProof, txHash
        )
      s.cryptarchiaLedger = r.state
      balance = ?balance.checkedAdd(r.balance)
    else:
      return err(UnsupportedOp)
  ok((state: s, balance: balance))

proc tryApplyTxns*(
    state: sink LedgerState,
    txs: openArray[SignedMantleTx],
    epoch: EpochNumber,
    slot: SlotNumber,
): Result[LedgerState, LedgerError] =
  ## Applies a block's transactions in order. Each tx must net to zero
  ## balance — otherwise returns `UnbalancedTransaction` or
  ## `InsufficientBalance`.
  var s = state
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
): Ledger[Id] =
  ## Constructs a Ledger seeded with one `(id, state)` entry.
  var states = initTable[Id, LedgerState]()
  states[id] = state
  Ledger[Id](states: states, config: config)

func state*[Id](l: Ledger[Id], id: Id): Opt[LedgerState] =
  # `Table.[]` raises KeyError; `getOrDefault` doesn't. Two lookups, but
  # this is a cold-path API.
  if id in l.states:
    Opt.some(l.states.getOrDefault(id))
  else:
    Opt.none(LedgerState)

func config*[Id](l: Ledger[Id]): lent LedgerConfig =
  l.config

proc commitUpdate*[Id](
    l: var Ledger[Id],
    id: Id,
    epoch: EpochNumber,
    state: sink LedgerState,
) =
  ## Installs ``state`` at ``id`` and runs SDP epoch-boundary updates
  ## (withdrawal finalization, epoch snapshots) once the block is accepted.
  # TODO(EpochState): derive epoch from the consensus slot schedule and call
  # onEpochStarted only when the epoch advances, not on every block commit.
  onEpochStarted(state.sdp, epoch)
  l.states[id] = state

func pruneStateAt*[Id](l: var Ledger[Id], id: Id): bool =
  if id in l.states:
    l.states.del(id)
    true
  else:
    false

proc fromGenesis*(
    _: typedesc[LedgerState],
    sdp: sink SdpRegistry,
    genesisTxs: openArray[SignedMantleTx],
): Result[LedgerState, LedgerError] =
  ## Builds genesis ledger state from the genesis block's transactions.
  ## Ops run through pure transition cores (no proof or balance checks).
  var state = LedgerState(
    cryptarchiaLedger: CryptarchiaState.init(),
    sdp: sdp,
    mantleLedger: MantleState.init(),
  )
  const
    epoch = 0'u64
    slot = 0'u64
  for tx in genesisTxs:
    for op in tx.tx.ops:
      case op.payload.kind
      of Transfer:
        let r = ?state.cryptarchiaLedger.applyTransferState(
          state.sdp.state.lockedNotes, op.payload.transfer,
        )
        state.cryptarchiaLedger = r.state
      of ChannelInscribe:
        state.mantleLedger.channels = applyChannelInscribe(
          state.mantleLedger.channels, op.payload.channelInscribe, slot,
        )
      of SdpDeclare:
        ?applySdpDeclare(state.sdp, op.payload.sdpDeclare, epoch)
      else:
        return err(UnsupportedOp)
  # TODO(EpochState): genesis epoch-boundary handling should follow the same
  # consensus epoch schedule as commitUpdate once epoch management lands.
  onEpochStarted(state.sdp, epoch = 0'u64)
  ok(state)

proc prepareUpdate*[Id](
    l: Ledger[Id],
    id, parentId: Id,
    slot: SlotNumber,
    proof: ProofOfLeadership,
    txs: openArray[SignedMantleTx],
    epoch: EpochNumber,
): Result[tuple[id: Id, state: LedgerState], LedgerError] =
  ## Validates a block's header + transactions against the parent state.
  ## Caller invokes `commitUpdate` to install the result and run SDP
  ## epoch-boundary updates, or drops it to reject.
  if parentId notin l.states:
    return err(ParentNotFound)
  let
    parent = l.states.getOrDefault(parentId)
    afterHeader = ?parent.tryApplyHeader(slot, proof)
    afterTxs = ?afterHeader.tryApplyTxns(txs, epoch, slot)
  ok((id: id, state: afterTxs))

{.pop.}
