# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Composite `LedgerState` wrapping `CryptarchiaState`, and the chain-wide
## `Ledger[Id]` state-by-block-id map.

{.push raises: [], gcsafe.}

import
  results,
  std/[options, tables],
  ./[balance, types, cryptarchia_state, pol_verifier],
  ../core/mantle/[tx_types, tx_hashing, operations, proofs],
  ../core/sdp/[registry, ops],
  ../core/types

export types, cryptarchia_state, registry

type
  LedgerState* = object
    cryptarchiaLedger*: CryptarchiaState
    sdp*: SdpRegistry

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
    blockHeight: BlockNumber,
    genesis: bool = false,
): Result[tuple[state: LedgerState, balance: Balance], LedgerError] =
  ## Applies one transaction; returns the new state and the tx's net balance
  ## (sum of per-op balances). When ``genesis`` is true, ZK proofs are not
  ## checked (trusted deployment proofs).
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
          getLockedNotes(s.sdp.state),
          op.payload.transfer, proof.transferProof, txHash, genesis,
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
        blockHeight,
        genesis,
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
        blockHeight,
        genesis,
      )
    of SdpActive:
      if proof.kind != opfSdpActive:
        return err(InvalidProof)
      ?tryApplySdpActive(
        s.sdp,
        op.payload.sdpActive,
        proof.sdpActiveProof,
        txHash,
        blockHeight,
        genesis,
      )
    of ChannelInscribe:
      # Temporary: genesis deployment settings include channel_inscribe; skip
      # until ChannelInscribe ledger support lands.
      if not genesis:
        return err(UnsupportedOp)
      if proof.kind != opfChannelInscribe:
        return err(InvalidProof)
      discard
    else:
      return err(UnsupportedOp)
  ok((state: s, balance: balance))

proc tryApplyTxns*(
    state: sink LedgerState,
    txs: openArray[SignedMantleTx],
    blockHeight: BlockNumber,
    genesis: bool = false,
): Result[LedgerState, LedgerError] =
  ## Applies a block's transactions in order. Each tx must net to zero
  ## balance — otherwise returns `UnbalancedTransaction` or
  ## `InsufficientBalance`. When ``genesis`` is true, balance checks are
  ## skipped (trusted genesis mints need not balance).
  var s = state
  for tx in txs:
    let r = ?s.tryApplyTx(tx, blockHeight, genesis)
    s = r.state
    if genesis:
      continue
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
    blockHeight: BlockNumber,
    state: sink LedgerState,
) =
  ## Installs ``state`` at ``id`` and runs per-block SDP housekeeping (GC,
  ## session snapshots) once the block is accepted.
  let parentHeight = if blockHeight > 0: blockHeight - 1 else: 0'u64
  onBlockApplied(state.sdp, parentHeight, blockHeight)
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
  ## Builds genesis ledger state by applying genesis transactions at height 0.
  ## Genesis proofs are trusted from deployment settings and are not verified.
  var state = LedgerState(
    cryptarchiaLedger: CryptarchiaState.init(),
    sdp: sdp,
  )
  state = ?state.tryApplyTxns(genesisTxs, blockHeight = 0'u64, genesis = true)
  onBlockApplied(state.sdp, previousBlockNumber = 0'u64, blockNumber = 0'u64)
  ok(state)

proc prepareUpdate*[Id](
    l: Ledger[Id],
    id, parentId: Id,
    slot: SlotNumber,
    proof: ProofOfLeadership,
    txs: openArray[SignedMantleTx],
    blockHeight: BlockNumber,
): Result[tuple[id: Id, state: LedgerState], LedgerError] =
  ## Validates a block's header + transactions against the parent state.
  ## Caller invokes `commitUpdate` to install the result and run SDP
  ## block-boundary updates, or drops it to reject.
  if parentId notin l.states:
    return err(ParentNotFound)
  let
    parent = l.states.getOrDefault(parentId)
    afterHeader = ?parent.tryApplyHeader(slot, proof)
    afterTxs = ?afterHeader.tryApplyTxns(txs, blockHeight)
  ok((id: id, state: afterTxs))

{.pop.}
