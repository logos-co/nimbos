# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [Bedrock v1.1 — Mantle Specification v1.10.0 — Channel Operations](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md#channel-operations)

{.push raises: [], gcsafe.}

import
  std/sequtils,
  intops,
  results,
  libp2p/crypto/ed25519/ed25519,
  ./[types, channel_notes, cryptarchia_state, zksig_verify],
  ../core/[utils],
  ../core/mantle/[primitives, operations, proofs, tx_hashing, utxo],
  ../utils/hash_trie_map

export hash_trie_map, channel_notes

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
    transferThreshold*: TransferThreshold

  ChannelStore* = HashTrieMap[ChannelId, ChannelState]

func checkedAdd(a, b: TokenValue): Result[TokenValue, LedgerError] =
  ## Returns `a + b`, or `BalanceOutOfRange` on overflow.
  let (res, didOverflow) = overflowingAdd(a, b)
  if didOverflow: err(BalanceOutOfRange) else: ok(res)

func default_channel*(
    blockSlot: SlotNumber, keys: openArray[Ed25519PublicKey]
): ChannelState =
  ## Factory for a brand-new channel: thresholds = 1, no rotation, no
  ## liveness timeout.
  ChannelState(
    accreditedKeys: @keys,
    configurationThreshold: 1,
    tipMessage: default(Hash32),
    tipSlot: blockSlot,
    tipSequencer: 0,
    tipSequencerStartingSlot: blockSlot,
    postingTimeframe: 0,
    postingTimeout: 0,
    transferThreshold: 1,
  )

func round_robin*(
    blockSlot: SlotNumber, chan: ChannelState
): tuple[index: ChannelKeyIndex, startingSlot: SlotNumber] =
  # Returns the current sequencer index and its starting slot. Timeout
  # rotation (skip past silent sequencers) wins over scheduled rotation;
  # when both are zero, the current sequencer holds.
  # Underflow is impossible by design: tips never exceed `blockSlot` (seeded to
  # it, advanced only to `<= blockSlot`) and per-fork slots are monotonic.
  let
    elapsed = blockSlot - chan.tipSlot
    duration = blockSlot - chan.tipSequencerStartingSlot
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
    proof: ChannelMultiSigProof,
    keys: openArray[Ed25519PublicKey],
    threshold: uint16,
    txHash: Hash32,
): Result[void, LedgerError] =
  doAssert proof.signatures.len == proof.indexes.len,
    "ChannelMultiSigProof: signatures and indexes length mismatch"
  if proof.signatures.len != int(threshold):
    return err(ThresholdUnmet)
  for i, idx in proof.indexes:
    if int(idx) >= keys.len:
      return err(InvalidTxProof)
    if not verify(proof.signatures[i], txHash, keys[idx]):
      return err(InvalidTxProof)
  ok()

func assert_spendable(
    channelNotes: ChannelNotes,
    utxos: UtxoStore,
    lockedNotes: LockedNotes,
    inputs: openArray[NoteId],
    channel: Opt[ChannelId],
): Result[void, LedgerError] =
  ## Spendability of `inputs`: unlocked and unspent. With `channel` set they
  ## must be its notes, otherwise no channel may own them.
  ## Note: Assumes non-empty and unique inputs (no double spend) are verified
  ## statelessly at ingress via `validateMantleTxStateless`.
  for inputId in inputs:
    if inputId in lockedNotes:
      return err(LockedNote)
    if inputId notin utxos:
      return err(InvalidNote)
  let owner = channel.valueOr:
    if inputs.anyIt(channelNotes.isChannelNote(it)):
      return err(ChannelNoteSpend)
    return ok()
  if not inputs.allIt(channelNotes.isChannelNoteOf(it, owner)):
    return err(NotAChannelNote)
  ok()

func validateChannelInscribe*(
    channels: ChannelStore,
    op: ChannelInscribePayload,
    blockSlot: SlotNumber,
): Result[void, LedgerError] =
  ## Read-only checks for ChannelInscribe. If the channel exists, the parent
  ## must match its `tipMessage` and the signer must be the current
  ## round-robin sequencer. JIT path requires `parent == ZERO`.
  ## Note: Assumes signer Ed25519 signature is verified statelessly at ingress
  ## via `validateMantleTxStateless`.
  let chanOpt = channels.get(op.channelId)
  if chanOpt.isSome:
    let chan = chanOpt.get
    if op.parent != chan.tipMessage:
      return err(InvalidParent)
    let (idx, _) = round_robin(blockSlot, chan)
    if op.signer != chan.accreditedKeys[idx]:
      return err(UnauthorizedSigner)
  elif not op.parent.isZero:
    return err(InvalidParent)

  ok()

func applyChannelInscribe*(
    channels: ChannelStore,
    op: ChannelInscribePayload,
    blockSlot: SlotNumber,
): ChannelStore =
  ## Mutation only; assumes `validateChannelInscribe` passed. JIT-creates
  ## the channel if absent, then advances sequencer + tipMessage + tipSlot.
  var chan = channels.get(op.channelId).valueOr:
    default_channel(blockSlot, [op.signer])
  let (newSeq, newStart) = round_robin(blockSlot, chan)
  chan.tipSequencer = newSeq
  chan.tipSequencerStartingSlot = newStart
  chan.tipMessage = opId(op)
  chan.tipSlot = blockSlot
  channels.insert(op.channelId, chan)

func validateChannelConfig*(
    channels: ChannelStore,
    op: ChannelConfigPayload,
    proof: ChannelMultiSigProof,
    txHash: Hash32,
): Result[void, LedgerError] =
  ## Read-only checks for ChannelConfig. If the channel exists, verifies
  ## `configuration_threshold` signatures from current accredited keys.
  ## On JIT-create path no signature is required.
  ## Note: Assumes config structure (non-empty keys, valid thresholds) is
  ## verified statelessly at ingress via `validateMantleTxStateless`.
  channels.get(op.channel).isErrOr:
    ?verifyChannelMultiSig(
      proof, value.accreditedKeys, value.configurationThreshold, txHash)
  ok()

func applyChannelConfig*(
    channels: ChannelStore,
    op: ChannelConfigPayload,
    blockSlot: SlotNumber,
): ChannelStore =
  ## Mutation only; assumes `validateChannelConfig` passed. Overwrites the
  ## channel's keys/thresholds/rotation, or JIT-creates with `op.keys`.
  var chan = channels.get(op.channel).valueOr:
    default_channel(blockSlot, op.keys)
  chan.accreditedKeys = op.keys
  chan.configurationThreshold = op.configurationThreshold
  chan.tipSequencer = 0
  chan.tipSequencerStartingSlot = blockSlot
  chan.postingTimeframe = op.postingTimeframe
  chan.postingTimeout = op.postingTimeout
  chan.transferThreshold = op.transferThreshold
  chan.tipSlot = blockSlot
  chan.tipMessage = opId(op)
  channels.insert(op.channel, chan)

proc validateChannelDeposit*(
    channels: ChannelStore,
    channelNotes: ChannelNotes,
    cs: CryptarchiaState,
    lockedNotes: LockedNotes,
    op: ChannelDepositPayload,
    sig: ZkSigProof,
    txHash: Hash32,
): Result[void, LedgerError] =
  ## Read-only checks for ChannelDeposit.
  if op.channel notin channels:
    return err(ChannelNotFound)
  ?assert_spendable(
    channelNotes, cs.utxos, lockedNotes, op.inputs, Opt.none(ChannelId))

  var pks = newSeqOfCap[ZkPublicKey](op.inputs.len)
  for inputId in op.inputs:
    let utxo = cs.utxos.get(inputId).valueOr:
      return err(InvalidNote) # unreachable: assert_spendable checked presence
    pks.add(utxo.note.zkPublicKey)

  ?verifyZkSig(sig, txHash, pks)
  ok()

func applyChannelDeposit*(
    channelNotes: ChannelNotes,
    cs: sink CryptarchiaState,
    op: ChannelDepositPayload,
): Result[tuple[channelNotes: ChannelNotes, cs: CryptarchiaState], LedgerError] =
  ## Mutation only; assumes `validateChannelDeposit` passed. Consumes the
  ## inputs and re-creates identical notes under the deposit's OpId.
  # The fresh NoteId resets ageing and blocks deposit replay.
  var notes = channelNotes
  let depositOpId = opId(op)
  for i, inputId in op.inputs:
    let (newStore, removedUtxo) = cs.utxos.remove(inputId).valueOr:
      return err(InvalidNote) # unreachable if validate passed
    let
      u = Utxo(opId: depositOpId, outputIndex: uint64(i), note: removedUtxo.note)
      uid = u.id
    cs.utxos = newStore.insert(uid, u).store
    notes = ?notes.registerChannelNote(uid, op.channel)
  ok((notes, cs))

func validateChannelWithdraw*(
    channels: ChannelStore,
    channelNotes: ChannelNotes,
    cs: CryptarchiaState,
    lockedNotes: LockedNotes,
    op: ChannelWithdrawPayload,
    proof: ChannelMultiSigProof,
    txHash: Hash32,
): Result[void, LedgerError] =
  ## Read-only checks for ChannelWithdraw.
  let chan = channels.get(op.channel).valueOr:
    return err(ChannelNotFound)
  ?assert_spendable(
    channelNotes, cs.utxos, lockedNotes, op.inputs, Opt.some(op.channel))
  ?verifyChannelMultiSig(
    proof, chan.accreditedKeys, chan.transferThreshold, txHash)
  ok()

func applyChannelWithdraw*(
    channelNotes: ChannelNotes, op: ChannelWithdrawPayload
): Result[ChannelNotes, LedgerError] =
  ## Mutation only; assumes `validateChannelWithdraw` passed. Releases the
  ## inputs; the UTXO set is untouched.
  # Notes keep their NoteId, value and ZkPublicKey, so ageing never resets.
  var notes = channelNotes
  for inputId in op.inputs:
    notes = ?notes.unregisterChannelNote(inputId, op.channel)
  ok(notes)

func validateChannelTransfer*(
    channels: ChannelStore,
    channelNotes: ChannelNotes,
    cs: CryptarchiaState,
    lockedNotes: LockedNotes,
    op: ChannelTransferPayload,
    proof: ChannelMultiSigProof,
    txHash: Hash32,
): Result[void, LedgerError] =
  ## Read-only checks for ChannelTransfer.
  ## Note: Assumes non-zero output notes and non-empty/unique inputs are verified
  ## statelessly at ingress via `validateMantleTxStateless`.
  var outflow: TokenValue = 0
  for outNote in op.outputs:
    outflow = ?outflow.checkedAdd(outNote.value)

  let chan = channels.get(op.channel).valueOr:
    return err(ChannelNotFound)
  ?assert_spendable(
    channelNotes, cs.utxos, lockedNotes, op.inputs, Opt.some(op.channel))

  var inflow: TokenValue = 0
  for inputId in op.inputs:
    let utxo = cs.utxos.get(inputId).valueOr:
      return err(InvalidNote) # unreachable: assert_spendable checked presence
    inflow = ?inflow.checkedAdd(utxo.note.value)
  if inflow != outflow:
    return err(UnbalancedTransfer)

  ?verifyChannelMultiSig(
    proof, chan.accreditedKeys, chan.transferThreshold, txHash)
  ok()

func applyChannelTransfer*(
    channelNotes: ChannelNotes,
    cs: sink CryptarchiaState,
    op: ChannelTransferPayload,
): Result[tuple[channelNotes: ChannelNotes, cs: CryptarchiaState], LedgerError] =
  ## Mutation only; assumes `validateChannelTransfer` passed. Reassigns the
  ## inputs' value to the outputs' keys, which stay owned by the channel.
  var notes = channelNotes
  for inputId in op.inputs:
    let (newStore, _) = cs.utxos.remove(inputId).valueOr:
      return err(InvalidNote) # unreachable if validate passed
    cs.utxos = newStore
    notes = ?notes.unregisterChannelNote(inputId, op.channel)

  let transferOpId = opId(op)
  for i, outNote in op.outputs:
    let
      u = Utxo(opId: transferOpId, outputIndex: uint64(i), note: outNote)
      uid = u.id
    cs.utxos = cs.utxos.insert(uid, u).store
    notes = ?notes.registerChannelNote(uid, op.channel)
  ok((notes, cs))

{.pop.}
