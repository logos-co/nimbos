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
  ./types

export types

type
  SdpState* = object
    declarations*: Table[DeclarationId, DeclarationInfo]
    lockedNotes*: Table[NoteId, LockedNote]

func getDeclaration*(
    state: SdpState, id: DeclarationId,
): Opt[DeclarationInfo] =
  if id notin state.declarations:
    Opt.none(DeclarationInfo)
  else:
    Opt.some(state.declarations.getOrDefault(id))

func getLockedNote*(state: SdpState, id: NoteId): Opt[LockedNote] =
  if id notin state.lockedNotes:
    Opt.none(LockedNote)
  else:
    Opt.some(state.lockedNotes.getOrDefault(id))

func getLockedNotes*(state: SdpState): HashSet[NoteId] =
  ## Note ids that currently hold at least one SDP declaration.
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

func addDeclarationToLockedNote*(
    state: var SdpState,
    noteId: NoteId,
    declId: DeclarationId,
    lockedUntil: BlockNumber,
) =
  var note = state.lockedNotes.mgetOrPut(noteId, LockedNote())
  note.declarations.incl(declId)
  note.lockedUntil = max(lockedUntil, note.lockedUntil)
  state.lockedNotes[noteId] = note

func removeDeclarationFromLockedNote*(
    state: var SdpState,
    noteId: NoteId,
    declId: DeclarationId,
) =
  if noteId notin state.lockedNotes:
    return
  var note = state.lockedNotes.mgetOrPut(noteId, LockedNote())
  note.declarations.excl(declId)
  if note.declarations.len == 0:
    state.lockedNotes.del(noteId)
  else:
    state.lockedNotes[noteId] = note

func isDeclarationGarbage*(
    info: DeclarationInfo,
    params: ServiceParameters,
    blockHeight: BlockNumber,
): bool =
  ## Returns whether ``info`` may be removed by garbage collection at
  ## ``blockHeight`` per SDP § Garbage Collection.
  let sessionLen = params.sessionLength
  if info.withdrawn != 0:
    let retentionBlocks = params.retentionPeriod * sessionLen
    if info.withdrawn + retentionBlocks < blockHeight:
      return true
  let inactiveRetentionBlocks =
    (params.inactivityPeriod + params.retentionPeriod) * sessionLen
  info.active + inactiveRetentionBlocks < blockHeight

func collectGarbage*(
    state: var SdpState,
    parameters: Table[ServiceType, ServiceParameters],
    blockHeight: BlockNumber,
) =
  ## Remove ``DeclarationInfo`` entries past retention or inactivity windows.
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
    removeDeclarationFromLockedNote(state, info.lockedNoteId, declId)
    state.declarations.del(declId)

{.pop.}
