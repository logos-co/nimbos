# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## In-memory persistent UTXO store: a `HashTrieMap[NoteId, (Utxo, leafIndex)]`
## side map paired with a `DynamicMerkleTree[NoteId, Poseidon2Hasher]` for
## cryptographic membership proofs.

{.push raises: [], gcsafe.}

import results

import poseidon2/types   # `==` for F

import ../core/mantle/[primitives, utxo]
import ../utils/[dynamic_merkle_tree, hash_trie_map]
import "../zk/poseidon2/hasher"

type
  UtxoStoreError* = enum
    NotFound

  UtxoStore* = object
    utxos: HashTrieMap[NoteId, tuple[utxo: Utxo, leafIndex: int]]
    tree:  DynamicMerkleTree[NoteId, Poseidon2Hasher]

func init*(_: typedesc[UtxoStore]): UtxoStore =
  UtxoStore(
    utxos: HashTrieMap[NoteId, tuple[utxo: Utxo, leafIndex: int]].init(),
    tree:  DynamicMerkleTree[NoteId, Poseidon2Hasher].init())

func len*(s: UtxoStore): int =
  s.utxos.len

func isEmpty*(s: UtxoStore): bool =
  s.utxos.isEmpty

func utxos*(s: UtxoStore):
    lent HashTrieMap[NoteId, tuple[utxo: Utxo, leafIndex: int]] =
  ## Read-only view of the underlying NoteId → (Utxo, leafIndex) map.
  s.utxos

func contains*(s: UtxoStore; id: NoteId): bool =
  id in s.utxos

func get*(s: UtxoStore; id: NoteId): Opt[Utxo] =
  ## Returns the Utxo for ``id``, or ``Opt.none`` if absent.
  let entry = s.utxos.get(id)
  if entry.isSome:
    Opt.some(entry.get.utxo)
  else:
    Opt.none(Utxo)

func insert*(s: UtxoStore; id: NoteId; utxo: sink Utxo):
    tuple[store: UtxoStore, leafIndex: int] =
  ## Inserts ``(id, utxo)``. Asserts the id isn't already present.
  doAssert id notin s.utxos, "UtxoStore: duplicate NoteId"
  let
    (newTree, leafIndex) = s.tree.insert(id)
    newUtxos = s.utxos.insert(id, (utxo, leafIndex))
  (UtxoStore(utxos: newUtxos, tree: newTree), leafIndex)

func remove*(s: UtxoStore; id: NoteId):
    Result[tuple[store: UtxoStore, utxo: Utxo], UtxoStoreError] =
  ## Removes the entry for ``id`` and returns the removed Utxo.
  let entry = s.utxos.get(id)
  if entry.isNone:
    return err(NotFound)
  let
    (removedUtxo, leafIndex) = entry.get
    newTree  = s.tree.remove(leafIndex)
    newUtxos = s.utxos.remove(id)
  ok((UtxoStore(utxos: newUtxos, tree: newTree), removedUtxo))

func root*(s: UtxoStore): F =
  ## Current Merkle root over the set of populated UTXO NoteIds.
  s.tree.root

func path*(s: UtxoStore; id: NoteId): Opt[MerklePath] =
  ## Inclusion proof for ``id``, or ``Opt.none`` if the id isn't present.
  let entry = s.utxos.get(id)
  if entry.isNone:
    return Opt.none(MerklePath)
  s.tree.path(entry.get.leafIndex)

func `==`*(a, b: UtxoStore): bool =
  ## Structural equality: same NoteId→Utxo map and same Merkle root.
  a.tree.root == b.tree.root and a.utxos == b.utxos

{.pop.}
