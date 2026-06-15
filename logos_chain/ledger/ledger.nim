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
  std/tables,
  ./[balance, types, cryptarchia_state, locked_notes, pol_verifier,zk_verifier],
  ../core/mantle/[tx_types, tx_hashing, operations, proofs],
  ../core/types

export types, cryptarchia_state

type
  LedgerState* = object
    cryptarchiaLedger*: CryptarchiaState

  Ledger*[Id] = object
    states: Table[Id, LedgerState]
    config: LedgerConfig

func fromUtxos*(
    _: typedesc[LedgerState],
    utxos: openArray[Utxo],
    config: LedgerConfig = LedgerConfig(),
): LedgerState =
  ## Builds a genesis-style state from the given UTXO set.
  LedgerState(cryptarchiaLedger: CryptarchiaState.init(utxos))

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

func tryApplyTx*(
    state: sink LedgerState,
    tx: SignedMantleTx,
    lockedNotes: LockedNotes,
    verifier: ZkSigVerifier,
): Result[tuple[state: LedgerState, balance: Balance], LedgerError] =
  ## Applies one transaction; returns the new state and the tx's net balance
  ## (sum of per-op balances).

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
          lockedNotes, op.payload.transfer, proof.transferProof, txHash, verifier
        )
      s = LedgerState(cryptarchiaLedger: r.state)
      balance = ?balance.checkedAdd(r.balance)
    else:
      return err(UnsupportedOp)
  ok((state: s, balance: balance))

func tryApplyTxns*(
    state: sink LedgerState,
    txs: openArray[SignedMantleTx],
    lockedNotes: LockedNotes,
    verifier: ZkSigVerifier,
): Result[LedgerState, LedgerError] =
  ## Applies a block's transactions in order. Each tx must net to zero
  ## balance — otherwise returns `UnbalancedTransaction` or
  ## `InsufficientBalance`.
  var s = state
  for tx in txs:
    let r = ?s.tryApplyTx(tx, lockedNotes, verifier)
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

func commitUpdate*[Id](l: var Ledger[Id], id: Id, state: LedgerState) =
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
    lockedNotes: LockedNotes,
    verifier: ZkSigVerifier,
): Result[tuple[id: Id, state: LedgerState], LedgerError] =
  ## Validates a block's header + transactions against the parent state.
  ## Caller invokes `commitUpdate` to install the result, or drops it to reject.
  if parentId notin l.states:
    return err(ParentNotFound)
  let
    parent = l.states.getOrDefault(parentId)
    afterHeader = ?parent.tryApplyHeader(slot, proof)
    afterTxs = ?afterHeader.tryApplyTxns(txs, lockedNotes, verifier)
  ok((id: id, state: afterTxs))

{.pop.}
