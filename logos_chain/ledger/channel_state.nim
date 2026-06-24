# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## `ChannelState` + `ChannelStore`, and the four channel op apply procs.
## Spec: [v1.5.0 Mantle](https://nomos-tech.notion.site/1-5-0-Mantle-33d261aa09df8051b0d0cd4d5ddade85)
## Channel Operations section.
##
## Inscribe, Config and Withdraw are split into `validateChannelX` (read-only)
## and `applyChannelX` (sink-receiving, cannot fail if validate passed) procs.
## Deposit follows the `applyTransferState` / `tryApplyTransfer`
## apply-then-verify pattern from cryptarchia_state.nim because its zkSig
## verify consumes pks collected during UTXO removal — splitting would
## require two passes over the inputs.
##
## The validate-then-apply composition lives on `MantleState` (the
## consumer); these primitives are the building blocks.

{.push raises: [], gcsafe.}

import
  std/tables,
  results,
  libp2p/crypto/ed25519/ed25519,
  ./[balance, types, cryptarchia_state, locked_notes],
  ../core/[utils],
  ../core/mantle/[primitives, operations, proofs, tx_hashing, utxo],
  ../zk/zksign

export tables, balance

type
  ChannelState* = object
    accreditedKeys*: seq[Ed25519PublicKey]
    configurationThreshold*: ConfigurationThreshold
    tipMessage*: Hash32
    tipSlot*: SlotNumber
    tipSequencer*: ChannelKeyIndex
    tipSequencerStartingSlot*: SlotNumber
    postingTimeframe*: PostingTimeframe
    postingTimeout*: PostingTimeout
    balance*: TokenValue
    withdrawalNonce*: uint32
    withdrawThreshold*: WithdrawThreshold

  ChannelStore* = Table[ChannelId, ChannelState]

func saturatingSub(a, b: SlotNumber): SlotNumber =
  # Matches Rust's `Slot::saturating_sub` (commit 8abfef258). Defensive
  # against `tip_slot > block_slot`, which shouldn't happen under normal
  # consensus but is cheaper to guard than to debug if it ever does.
  if a >= b: a - b else: 0

func defaultChannel*(
    blockSlot: SlotNumber, keys: openArray[Ed25519PublicKey]
): ChannelState =
  ## Spec `default_channel`: thresholds = 1, no rotation, no liveness
  ## timeout, zero balance. The JIT factory for a brand-new channel.
  ChannelState(
    accreditedKeys: @keys,
    configurationThreshold: 1,
    tipMessage: default(Hash32),
    tipSlot: blockSlot,
    tipSequencer: 0,
    tipSequencerStartingSlot: blockSlot,
    postingTimeframe: 0,
    postingTimeout: 0,
    balance: 0,
    withdrawalNonce: 0,
    withdrawThreshold: 1,
  )

func roundRobin*(
    blockSlot: SlotNumber, chan: ChannelState
): tuple[index: ChannelKeyIndex, startingSlot: SlotNumber] =
  ## Spec `round_robin`. Timeout rotation (skip past silent sequencers) wins
  ## over scheduled-rotation; both zero → current sequencer holds.
  let
    elapsed = saturatingSub(blockSlot, chan.tipSlot)
    duration = saturatingSub(blockSlot, chan.tipSequencerStartingSlot)
    numKeys = lenu64(chan.accreditedKeys)

  if chan.postingTimeout != 0 and elapsed >= SlotNumber(chan.postingTimeout):
    let
      timedOut = elapsed div SlotNumber(chan.postingTimeout)
      index =
        ChannelKeyIndex((uint64(chan.tipSequencer) + timedOut) mod numKeys)
      startingSlot = chan.tipSlot + timedOut * SlotNumber(chan.postingTimeout)
    (index, startingSlot)
  elif chan.postingTimeframe != 0:
    let
      rotations = duration div SlotNumber(chan.postingTimeframe)
      index =
        ChannelKeyIndex((uint64(chan.tipSequencer) + rotations) mod numKeys)
      startingSlot =
        chan.tipSequencerStartingSlot + rotations * SlotNumber(chan.postingTimeframe)
    (index, startingSlot)
  else:
    (chan.tipSequencer, chan.tipSequencerStartingSlot)

func verifyChannelMultiSig(
    proof: ChannelWithdrawOpProof,
    keys: openArray[Ed25519PublicKey],
    threshold: uint16,
    txHash: Hash32,
): Result[void, LedgerError] =
  # Assumes `signatures.len == indexes.len` and strict-increasing indexes —
  # both enforced by the codec at decode time.
  if proof.signatures.len != int(threshold):
    return err(ThresholdUnmet)
  for i in 0 ..< proof.signatures.len:
    let idx = proof.indexes[i]
    if int(idx) >= keys.len:
      return err(InvalidProof)
    if not verify(proof.signatures[i], txHash, keys[idx]):
      return err(InvalidProof)
  ok()

func validateChannelInscribe*(
    channels: ChannelStore,
    op: ChannelInscribePayload,
    sig: Ed25519Signature,
    txHash: Hash32,
    blockSlot: SlotNumber,
): Result[void, LedgerError] =
  ## Read-only checks for ChannelInscribe. If the channel exists, the parent
  ## must match its `tipMessage` and the signer must be the current
  ## round-robin sequencer. JIT path requires `parent == ZERO`. Signature
  ## must verify against `op.signer` over `txHash`.
  if op.channelId in channels:
    let chan = channels.getOrDefault(op.channelId)
    if op.parent != chan.tipMessage:
      return err(InvalidParent)
    let (idx, _) = roundRobin(blockSlot, chan)
    if op.signer != chan.accreditedKeys[idx]:
      return err(UnauthorizedSigner)
  elif op.parent != static(default(Hash32)):
    return err(InvalidParent)

  if not verify(sig, txHash, op.signer):
    return err(InvalidProof)
  ok()

func applyChannelInscribe*(
    channels: sink ChannelStore,
    op: ChannelInscribePayload,
    blockSlot: SlotNumber,
): ChannelStore =
  ## Mutation only; assumes `validateChannelInscribe` passed. JIT-creates
  ## the channel if absent, then advances sequencer + tipMessage + tipSlot.
  var chan =
    if op.channelId in channels: channels.getOrDefault(op.channelId)
    else: defaultChannel(blockSlot, [op.signer])
  let (newSeq, newStart) = roundRobin(blockSlot, chan)
  chan.tipSequencer = newSeq
  chan.tipSequencerStartingSlot = newStart
  chan.tipMessage = opId(op)
  chan.tipSlot = blockSlot
  channels[op.channelId] = chan
  channels

func validateChannelConfig*(
    channels: ChannelStore,
    op: ChannelConfigPayload,
    proof: ChannelWithdrawOpProof,
    txHash: Hash32,
): Result[void, LedgerError] =
  ## Read-only checks for ChannelConfig. Validates well-formedness, and if
  ## the channel exists, verifies `configuration_threshold` signatures from
  ## current accredited keys. JIT-create path requires no signature
  ## (spec/Rust gap).
  if op.configurationThreshold == 0 or op.withdrawThreshold == 0 or op.keys.len == 0:
    return err(InvalidChannelConfig)

  if op.channel in channels:
    let chan = channels.getOrDefault(op.channel)
    ?verifyChannelMultiSig(
      proof, chan.accreditedKeys, chan.configurationThreshold, txHash)
  ok()

func applyChannelConfig*(
    channels: sink ChannelStore,
    op: ChannelConfigPayload,
    blockSlot: SlotNumber,
): ChannelStore =
  ## Mutation only; assumes `validateChannelConfig` passed. Overwrites the
  ## channel's keys/thresholds/rotation, or JIT-creates with `op.keys`.
  var chan =
    if op.channel in channels: channels.getOrDefault(op.channel)
    else: defaultChannel(blockSlot, op.keys)
  chan.accreditedKeys = op.keys
  chan.configurationThreshold = op.configurationThreshold
  chan.tipSequencer = 0
  chan.tipSequencerStartingSlot = blockSlot
  chan.postingTimeframe = op.postingTimeframe
  chan.postingTimeout = op.postingTimeout
  chan.withdrawThreshold = op.withdrawThreshold
  chan.tipSlot = blockSlot
  chan.tipMessage = opId(op)
  channels[op.channel] = chan
  channels

func applyChannelDepositState*(
    channels: sink ChannelStore,
    cs: sink CryptarchiaState,
    lockedNotes: LockedNotes,
    op: ChannelDepositPayload,
): Result[
    tuple[
      channels: ChannelStore,
      cs: CryptarchiaState,
      balance: Balance,
      pks: seq[ZkPublicKey],
    ],
    LedgerError,
] =
  ## Pure state transition for ChannelDeposit. Removes inputs from UTXOs,
  ## accumulates ZkPublicKeys + total input value, credits the channel
  ## balance. Caller verifies the zkSig over the returned pks.
  ## Returned tx-balance contribution is negative (inputs consumed, no UTXO
  ## outputs from this op).
  if op.channel notin channels:
    return err(ChannelNotFound)

  var
    inflow = Balance.zero
    pks = newSeqOfCap[ZkPublicKey](op.inputs.len)
  for inputId in op.inputs:
    if lockedNotes.contains(inputId):
      return err(LockedNote)
    let (newStore, removedUtxo) = cs.utxos.remove(inputId).valueOr:
      return err(InvalidNote)
    cs = CryptarchiaState(utxos: newStore)
    inflow = ?inflow.checkedAdd(i128(removedUtxo.note.value))
    pks.add(removedUtxo.note.zkPublicKey)

  # Spec uses raw `+=`; Rust uses checked_add → BalanceOverflow. Match Rust.
  var chan = channels.getOrDefault(op.channel)
  if inflow > i128(TokenValue.high - chan.balance):
    return err(BalanceOverflow)
  chan.balance += inflow.truncate(uint64)
  channels[op.channel] = chan

  let net = ?Balance.zero.checkedSub(inflow)
  ok((channels, cs, net, pks))

proc tryApplyChannelDeposit*(
    channels: sink ChannelStore,
    cs: sink CryptarchiaState,
    lockedNotes: LockedNotes,
    op: ChannelDepositPayload,
    sig: ZkSigProof,
    txHash: Hash32,
): Result[
    tuple[channels: ChannelStore, cs: CryptarchiaState, balance: Balance],
    LedgerError,
] =
  let
    r = ?applyChannelDepositState(channels, cs, lockedNotes, op)
    input = zksignInput(r.pks, frFromBytesLEModOrder(txHash)).valueOr:
      return err(InvalidProof)
    verified = zksign.verify(sig, input).valueOr:
      return err(VerifierNotInitialised)
  if not verified:
    return err(InvalidProof)

  ok((r.channels, r.cs, r.balance))

func validateChannelWithdraw*(
    channels: ChannelStore,
    op: ChannelWithdrawPayload,
    proof: ChannelWithdrawOpProof,
    txHash: Hash32,
): Result[Balance, LedgerError] =
  ## Read-only checks for ChannelWithdraw. Returns the validated outflow
  ## (sum of output values) so apply doesn't recompute. Catches all error
  ## variants up front including `WithdrawNonceOverflow`.
  if op.channel notin channels:
    return err(ChannelNotFound)

  var outflow = Balance.zero
  for outNote in op.outputs:
    if outNote.value == 0:
      return err(ZeroValueNote)
    outflow = ?outflow.checkedAdd(i128(outNote.value))

  let chan = channels.getOrDefault(op.channel)
  if chan.withdrawalNonce != op.opIdNonce:
    return err(InvalidWithdrawNonce)
  if chan.withdrawalNonce == high(uint32):
    return err(WithdrawNonceOverflow)
  if outflow > i128(chan.balance):
    return err(InsufficientBalance)
  ?verifyChannelMultiSig(
    proof, chan.accreditedKeys, chan.withdrawThreshold, txHash)
  ok(outflow)

func applyChannelWithdraw*(
    channels: sink ChannelStore,
    cs: sink CryptarchiaState,
    op: ChannelWithdrawPayload,
    outflow: Balance,
): tuple[channels: ChannelStore, cs: CryptarchiaState] =
  ## Mutation only; assumes `validateChannelWithdraw` passed. Drains the
  ## channel balance, bumps the withdraw nonce, and inserts the output
  ## UTXOs.
  var chan = channels.getOrDefault(op.channel)
  chan.balance -= outflow.truncate(uint64)
  chan.withdrawalNonce += 1
  channels[op.channel] = chan

  let withdrawOpId = opId(op)
  for i, outNote in op.outputs:
    let u = Utxo(opId: withdrawOpId, outputIndex: uint64(i), note: outNote)
    cs = CryptarchiaState(utxos: cs.utxos.insert(u.id, u).store)
  (channels, cs)

{.pop.}
