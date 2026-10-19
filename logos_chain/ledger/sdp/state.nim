# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP declaration records and in-memory validator state store.
## Spec: [Service Declaration Protocol v1.6.0](https://github.com/logos-co/logos-lips/blob/7c2ec59fadcdc2ba0ae74ff7600a14b55d90efcd/docs/blockchain/raw/bedrock-service-declaration-protocol.md)

{.push raises: [], gcsafe.}

import
  results,
  std/[sequtils, sets],
  ../../core/mantle/primitives,
  ../../utils/hash_trie_map

export primitives, results, hash_trie_map

const SnapshotFinalizationDelay* = EpochNumber(2)
  ## Epochs a registry change waits before the snapshot that carries it is
  ## the one in force.

type
  MinStake* = object
    stakeThreshold*: uint64
    epoch*: EpochNumber

  ServiceParameters* = object
    inactivityPeriod*: NumberOfEpochs
    epoch*: EpochNumber

  DeclarationInfo* = object
    service*: ServiceType
    providerId*: Ed25519PublicKey
    lockedNoteId*: NoteId
    zkId*: ZkPublicKey
    locators*: seq[Locator]
    created*: EpochNumber
    active*: Opt[EpochNumber]
    withdrawAt*: Opt[EpochNumber]
    nonce*: Nonce

  LockedNotes* = HashTrieMap[NoteId, HashSet[DeclarationId]]

  SdpState* = object
    declarations*: HashTrieMap[DeclarationId, DeclarationInfo]
    lockedNotes*: LockedNotes
    activeProviders*: HashTrieMap[tuple[service: ServiceType, providerId: Ed25519PublicKey], tuple[]]
    activeZkIds*: HashTrieMap[tuple[service: ServiceType, zkId: ZkPublicKey], tuple[]]

func init*(_: typedesc[SdpState]): SdpState =
  SdpState()

func `==`*(a, b: SdpState): bool =
  a.declarations == b.declarations and a.lockedNotes == b.lockedNotes and
  a.activeProviders == b.activeProviders and a.activeZkIds == b.activeZkIds

func getDeclaration*(
    state: SdpState, id: DeclarationId,
): Opt[DeclarationInfo] =
  state.declarations.get(id)

func getLockedNote*(state: SdpState, id: NoteId): Opt[HashSet[DeclarationId]] =
  state.lockedNotes.get(id)

func lockedNoteHasService*(
    state: SdpState, noteId: NoteId, service: ServiceType,
): bool =
  if noteId notin state.lockedNotes:
    false
  else:
    anyIt(state.lockedNotes.getOrDefault(noteId)):
      let info = getDeclaration(state, it)
      info.isSome and info.get().service == service

func hasProviderOrZkIdConflict*(
    state: SdpState, service: ServiceType, providerId: Ed25519PublicKey, zkId: ZkPublicKey,
): bool =
  ((service, providerId) in state.activeProviders) or ((service, zkId) in state.activeZkIds)

func insertDeclaration*(
    state: sink SdpState,
    id: DeclarationId,
    info: sink DeclarationInfo,
): SdpState =
  if id notin state.declarations:
    state.activeProviders = state.activeProviders.insert((info.service, info.providerId), ())
    state.activeZkIds = state.activeZkIds.insert((info.service, info.zkId), ())
  state.declarations = state.declarations.insert(id, info)
  state

func removeDeclaration*(
    state: sink SdpState,
    id: DeclarationId,
): SdpState =
  let info = state.declarations.get(id).valueOr:
    return state
  state.activeProviders = state.activeProviders.remove((info.service, info.providerId))
  state.activeZkIds = state.activeZkIds.remove((info.service, info.zkId))
  state.declarations = state.declarations.remove(id)
  state

func addDeclarationToLockedNote*(
    state: sink SdpState,
    noteId: NoteId,
    declId: DeclarationId,
): SdpState =
  var declIds = state.lockedNotes.getOrDefault(noteId)
  declIds.incl(declId)
  state.lockedNotes = state.lockedNotes.insert(noteId, declIds)
  state

func removeDeclarationFromLockedNote*(
    state: sink SdpState,
    noteId: NoteId,
    declId: DeclarationId,
): SdpState =
  if noteId notin state.lockedNotes:
    return state
  var declIds = state.lockedNotes.getOrDefault(noteId)
  declIds.excl(declId)
  if declIds.len == 0:
    state.lockedNotes = state.lockedNotes.remove(noteId)
  else:
    state.lockedNotes = state.lockedNotes.insert(noteId, declIds)
  state

func finalizeWithdrawals*(
    state: sink SdpState,
    currentEpoch: EpochNumber,
): SdpState =
  ## Removes the declarations past ``withdraw_at`` and unlocks their notes.
  for declId, info in state.declarations.pairs:
    let withdrawAt = info.withdrawAt.valueOr:
      continue
    # This is `withdrawAt + 1 <= currentEpoch` without the addition. The
    # addition can wrap at the EpochNumber limit.
    if withdrawAt < currentEpoch:
      state = removeDeclarationFromLockedNote(state, info.lockedNoteId, declId)
      state = removeDeclaration(state, declId)
  state

{.pop.}
