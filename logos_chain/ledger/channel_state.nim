# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [v1.5.0 Mantle](https://nomos-tech.notion.site/1-5-0-Mantle-33d261aa09df8051b0d0cd4d5ddade85)
## Channel Operations section.

{.push raises: [], gcsafe.}

import
  std/sets,
  intops,
  results,
  libp2p/crypto/ed25519/ed25519,
  ./[types, cryptarchia_state],
  ../core/[utils],
  ../core/mantle/[primitives, operations, proofs, tx_hashing, utxo],
  ../utils/hash_trie_map,
  ../zk/zksign

export hash_trie_map

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

  ChannelStore* = HashTrieMap[ChannelId, ChannelState]

func checkedAdd(a, b: TokenValue): Result[TokenValue, LedgerError] =
  ## Returns `a + b`, or `BalanceOverflow` on overflow.
  let (res, didOverflow) = overflowingAdd(a, b)
  if didOverflow: err(BalanceOverflow) else: ok(res)

func default_channel*(
    blockSlot: SlotNumber, keys: openArray[Ed25519PublicKey]
): ChannelState =
  ## Factory for a brand-new channel: thresholds = 1, no rotation, no
  ## liveness timeout, zero balance.
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
    proof: ChannelWithdrawOpProof,
    keys: openArray[Ed25519PublicKey],
    threshold: uint16,
    txHash: Hash32,
): Result[void, LedgerError] =
  doAssert proof.signatures.len == proof.indexes.len,
    "ChannelWithdrawOpProof: signatures and indexes length mismatch"
  if proof.signatures.len != int(threshold):
    return err(ThresholdUnmet)
  for i, idx in proof.indexes:
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

  if not verify(sig, txHash, op.signer):
    return err(InvalidProof)
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
    proof: ChannelWithdrawOpProof,
    txHash: Hash32,
): Result[void, LedgerError] =
  ## Read-only checks for ChannelConfig. Validates well-formedness, and if
  ## the channel exists, verifies `configuration_threshold` signatures from
  ## current accredited keys. On the JIT-create path (channel doesn't exist
  ## yet) no signature is required — there are no accredited keys to
  ## authenticate against.
  if op.keys.len == 0:
    return err(InvalidChannelConfig)
  # A threshold larger than `keys.len` can never be met — the resulting
  # channel would be permanently unreconfigurable and its funds unwithdrawable.
  if op.configurationThreshold == 0 or
      op.configurationThreshold.int > op.keys.len:
    return err(InvalidChannelConfig)
  if op.withdrawThreshold == 0 or op.withdrawThreshold.int > op.keys.len:
    return err(InvalidChannelConfig)

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
  chan.withdrawThreshold = op.withdrawThreshold
  chan.tipSlot = blockSlot
  chan.tipMessage = opId(op)
  channels.insert(op.channel, chan)

proc validateChannelDeposit*(
    channels: ChannelStore,
    cs: CryptarchiaState,
    lockedNotes: LockedNotes,
    op: ChannelDepositPayload,
    sig: ZkSigProof,
    txHash: Hash32,
): Result[void, LedgerError] =
  ## Read-only checks for ChannelDeposit.
  if op.channel notin channels:
    return err(ChannelNotFound)

  var seen: HashSet[NoteId]
  for inputId in op.inputs:
    if seen.containsOrIncl(inputId):
      return err(DoubleSpend)

  var pks = newSeqOfCap[ZkPublicKey](op.inputs.len)
  for inputId in op.inputs:
    if inputId in lockedNotes:
      return err(LockedNote)
    let utxo = cs.utxos.get(inputId).valueOr:
      return err(InvalidNote)
    pks.add(utxo.note.zkPublicKey)

  let
    input = zksignInput(pks, frFromBytesLEModOrder(txHash)).valueOr:
      return err(InvalidProof)
    verified = zksign.verify(sig, input).valueOr:
      return err(VerifierNotInitialised)
  if not verified:
    return err(InvalidProof)
  ok()

func applyChannelDeposit*(
    channels: ChannelStore,
    cs: CryptarchiaState,
    op: ChannelDepositPayload,
): Result[tuple[channels: ChannelStore, cs: CryptarchiaState], LedgerError] =
  ## Mutation-with-overflow-check; assumes `validateChannelDeposit` passed.
  ## Removes inputs and credits the channel balance.
  var
    store = cs.utxos
    chan = channels.getOrDefault(op.channel)
  for inputId in op.inputs:
    let (newStore, removedUtxo) = store.remove(inputId).valueOr:
      return err(InvalidNote)  # unreachable if validate passed
    store = newStore
    chan.balance = ?chan.balance.checkedAdd(removedUtxo.note.value)
  ok((channels.insert(op.channel, chan), CryptarchiaState(utxos: store, leader: cs.leader)))

func validateChannelWithdraw*(
    channels: ChannelStore,
    op: ChannelWithdrawPayload,
    proof: ChannelWithdrawOpProof,
    txHash: Hash32,
): Result[void, LedgerError] =
  ## Read-only checks for ChannelWithdraw.
  let chan = channels.get(op.channel).valueOr:
    return err(ChannelNotFound)

  var outflow: TokenValue = 0
  for outNote in op.outputs:
    if outNote.value == 0:
      return err(ZeroValueNote)
    outflow = ?outflow.checkedAdd(outNote.value)

  if chan.withdrawalNonce != op.opIdNonce:
    return err(InvalidWithdrawNonce)
  if chan.withdrawalNonce == high(uint32):
    return err(WithdrawNonceOverflow)
  if outflow > chan.balance:
    return err(InsufficientBalance)
  ?verifyChannelMultiSig(
    proof, chan.accreditedKeys, chan.withdrawThreshold, txHash)
  ok()

func applyChannelWithdraw*(
    channels: ChannelStore,
    cs: CryptarchiaState,
    op: ChannelWithdrawPayload,
): tuple[channels: ChannelStore, cs: CryptarchiaState] =
  ## Mutation only; assumes `validateChannelWithdraw` passed. Drains the
  ## channel balance, bumps the nonce, inserts output UTXOs.
  var
    chan = channels.getOrDefault(op.channel)
    store = cs.utxos
  let withdrawOpId = opId(op)
  for i, outNote in op.outputs:
    chan.balance -= outNote.value
    let u = Utxo(opId: withdrawOpId, outputIndex: uint64(i), note: outNote)
    store = store.insert(u.id, u).store
  chan.withdrawalNonce += 1
  (channels.insert(op.channel, chan), CryptarchiaState(utxos: store, leader: cs.leader))

{.pop.}
