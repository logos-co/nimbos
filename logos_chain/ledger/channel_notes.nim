# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Ledger registry of channel-owned notes: `NoteId` → owning `ChannelId`.
## Spec: [Mantle — Channel Notes](https://github.com/logos-co/logos-lips/blob/master/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md#channel-notes)

{.push raises: [], gcsafe.}

import
  results,
  ./types,
  ../core/mantle/primitives,
  ../utils/hash_trie_map

export hash_trie_map

type
  ChannelOwner* = object
    ## Boxes the owning `ChannelId`. A bare `array[32, byte]` map value fails
    ## to compile when read back out through `Opt[V]`.
    channel*: ChannelId

  ChannelNotes* = HashTrieMap[NoteId, ChannelOwner]

func isChannelNote*(notes: ChannelNotes, id: NoteId): bool =
  ## True when `id` is owned by some channel.
  id in notes

func isChannelNoteOf*(
    notes: ChannelNotes, id: NoteId, channel: ChannelId
): bool =
  ## True when `id` is a channel note owned by `channel`.
  let owner = notes.get(id).valueOr:
    return false
  owner.channel == channel

func registerChannelNote*(
    notes: ChannelNotes, id: NoteId, channel: ChannelId
): Result[ChannelNotes, LedgerError] =
  ## Claims `id` for `channel`. Fails when it already belongs to a channel.
  if notes.isChannelNote(id):
    return err(AlreadyChannelNote)
  ok(notes.insert(id, ChannelOwner(channel: channel)))

func unregisterChannelNote*(
    notes: ChannelNotes, id: NoteId, channel: ChannelId
): Result[ChannelNotes, LedgerError] =
  ## Releases `id` from `channel`. Fails when `channel` doesn't own it.
  if not notes.isChannelNoteOf(id, channel):
    return err(NotAChannelNote)
  ok(notes.remove(id))

{.pop.}
