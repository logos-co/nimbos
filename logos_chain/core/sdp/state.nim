# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## In-memory SDP validator state store.
## Spec: [1.0.0 Service Declaration Protocol](https://nomos-tech.notion.site/1-0-0-Service-Declaration-Protocol-1fd261aa09df819ca9f8eb2bdfd4ec1d)

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
    lockedNotes*: HashTrieMap[NoteId, LockedNote]

func init*(_: typedesc[SdpState]): SdpState =
  SdpState(
    declarations: HashTrieMap[DeclarationId, DeclarationInfo].init(),
    lockedNotes: HashTrieMap[NoteId, LockedNote].init(),
  )

func `==`*(a, b: SdpState): bool =
  a.declarations == b.declarations and a.lockedNotes == b.lockedNotes

func getDeclaration*(
    state: SdpState, id: DeclarationId,
): Opt[DeclarationInfo] =
  state.declarations.get(id)

func getLockedNote*(state: SdpState, id: NoteId): Opt[LockedNote] =
  state.lockedNotes.get(id)

func getLockedNotes*(state: SdpState): HashSet[NoteId] =
  var ids: HashSet[NoteId]
  for noteId, note in state.lockedNotes.pairs:
    if note.declarations.len > 0:
      ids.incl(noteId)
  ids

func lockedNoteHasService*(
    state: SdpState, noteId: NoteId, service: ServiceType,
): bool =
  if noteId notin state.lockedNotes:
    false
  else:
    anyIt(state.lockedNotes.getOrDefault(noteId).declarations):
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
    lockedUntil: BlockNumber,
): SdpState =
  var note = state.lockedNotes.getOrDefault(noteId)
  note.declarations.incl(declId)
  note.lockedUntil = max(lockedUntil, note.lockedUntil)
  state.lockedNotes = state.lockedNotes.insert(noteId, note)
  state

func removeDeclarationFromLockedNote*(
    state: sink SdpState,
    noteId: NoteId,
    declId: DeclarationId,
): SdpState =
  if noteId notin state.lockedNotes:
    return state
  var note = state.lockedNotes.getOrDefault(noteId)
  note.declarations.excl(declId)
  if note.declarations.len == 0:
    state.lockedNotes = state.lockedNotes.remove(noteId)
  else:
    state.lockedNotes = state.lockedNotes.insert(noteId, note)
  state

func isDeclarationGarbage*(
    info: DeclarationInfo,
    params: ServiceParameters,
    blockHeight: BlockNumber,
): bool =
  let sessionLen = params.sessionLength
  if info.withdrawn != 0:
    let retentionBlocks = params.retentionPeriod * sessionLen
    if info.withdrawn + retentionBlocks < blockHeight:
      return true
  let inactiveRetentionBlocks =
    (params.inactivityPeriod + params.retentionPeriod) * sessionLen
  info.active + inactiveRetentionBlocks < blockHeight

func collectGarbage*(
    state: sink SdpState,
    parameters: Table[ServiceType, ServiceParameters],
    blockHeight: BlockNumber,
): SdpState =
  let toRemove = mapIt(
    filterIt(toSeq(state.declarations.pairs),
      it[1].service in parameters and
      parameters.getOrDefault(it[1].service).timestamp <= blockHeight and
      isDeclarationGarbage(
        it[1], parameters.getOrDefault(it[1].service), blockHeight)),
    it[0],
  )
  for declId in toRemove:
    let info = state.declarations.getOrDefault(declId)
    state = removeDeclarationFromLockedNote(state, info.lockedNoteId, declId)
    state.declarations = state.declarations.remove(declId)
  state

{.pop.}
