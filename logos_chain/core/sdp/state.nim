# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## In-memory SDP validator state store.
## Spec: [1.1.0 Service Declaration Protocol](bedrock-service-declaration-protocol.md)

{.push raises: [], gcsafe.}

import
  results,
  std/[sequtils, sets, tables],
  ./types,
  ../../utils/hash_trie_map

export types, hash_trie_map

type
  SdpState* = object
    declarations*: HashTrieMap[DeclarationId, DeclarationInfo]
    lockedNotes*: LockedNotes

func init*(_: typedesc[SdpState]): SdpState =
  SdpState(
    declarations: HashTrieMap[DeclarationId, DeclarationInfo].init(),
    lockedNotes: LockedNotes.init(),
  )

func `==`*(a, b: SdpState): bool =
  a.declarations == b.declarations and a.lockedNotes == b.lockedNotes

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

func insertDeclaration*(
    state: sink SdpState,
    id: DeclarationId,
    info: sink DeclarationInfo,
): SdpState =
  state.declarations = state.declarations.insert(id, info)
  state

func removeDeclaration*(
    state: sink SdpState,
    id: DeclarationId,
): SdpState =
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
  ## Removes declarations whose ``withdraw_at <= current_epoch - 2`` and
  ## unlocks notes no longer bound to any declaration.
  if currentEpoch < 2:
    return state
  let threshold = currentEpoch - 2
  for declId, info in state.declarations.pairs:
    if info.withdrawAt.valueOr(high(EpochNumber)) <= threshold:
      state = removeDeclarationFromLockedNote(state, info.lockedNoteId, declId)
      state.declarations = state.declarations.remove(declId)
  state

{.pop.}
