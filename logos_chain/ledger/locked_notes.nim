# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Set of `NoteId`s that cannot be spent (held as SDP locked collateral).
## Populated by the SDP module.

{.push raises: [], gcsafe.}

import std/sets

import ../core/mantle/primitives

type LockedNotes* = object
  ids: HashSet[NoteId]

func init*(_: typedesc[LockedNotes]): LockedNotes =
  LockedNotes()

func init*(_: typedesc[LockedNotes], seed: openArray[NoteId]): LockedNotes =
  ## Test seam — lets tests construct a populated set without invoking SDP.
  var ids: HashSet[NoteId]
  for id in seed:
    ids.incl(id)
  LockedNotes(ids: ids)

func contains*(l: LockedNotes, id: NoteId): bool =
  id in l.ids

func len*(l: LockedNotes): int =
  l.ids.len

func isEmpty*(l: LockedNotes): bool =
  l.ids.len == 0

{.pop.}
