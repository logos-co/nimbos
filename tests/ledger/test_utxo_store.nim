# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import unittest2
import results

import poseidon2/types

import ../../logos_chain/core/mantle/[primitives, utxo]
import ../../logos_chain/ledger/utxo_store
import ../../logos_chain/utils/[dynamic_merkle_tree, hash_trie_map]
import "../../logos_chain/zk/poseidon2/hasher"
import ./test_helpers

suite "UtxoStore empty":
  test "fresh store is empty":
    let s = UtxoStore.init()
    check s.len == 0
    check s.isEmpty
    check s.root == DynamicMerkleTree[NoteId, Poseidon2Hasher].init().root

  test "two empty stores are equal":
    let
      a = UtxoStore.init()
      b = UtxoStore.init()
    check a == b

  test "lookups on empty store return none":
    let
      s = UtxoStore.init()
      id = mkUtxo().id
    check not s.contains(id)
    check s.get(id).isNone
    check s.path(id).isNone

suite "UtxoStore insert / lookup / path":
  test "single insert: contains/get/path all reflect the new entry":
    let
      s0 = UtxoStore.init()
      u = mkUtxo()
      id = u.id
      (s1, leafIndex) = s0.insert(id, u)
    check leafIndex == 0
    check s1.len == 1
    check s1.contains(id)
    check s1.get(id) == Opt.some(u)
    let p = s1.path(id)
    check p.isSome
    check Poseidon2Hasher.verifyPath(p.get, id.asField, s1.root)

  test "persistence: parent store unchanged by child insert":
    let
      s0 = UtxoStore.init()
      root0 = s0.root
      u = mkUtxo()
      (s1, _) = s0.insert(u.id, u)
    check s0.root == root0
    check s0.len == 0
    check s1.root != root0
    check s1.len == 1

  test "many inserts: each assigns the next contiguous leaf index":
    var
      s = UtxoStore.init()
      ids = newSeqOfCap[NoteId](50)
    for i in 0 ..< 50:
      let
        u = mkUtxo(value = Value(i + 1))
        (s2, idx) = s.insert(u.id, u)
      check idx == i
      ids.add(u.id)
      s = s2

    check s.len == 50
    for id in ids:
      check s.contains(id)
      check s.path(id).isSome

  test "duplicate insert panics":
    let
      s0 = UtxoStore.init()
      u = mkUtxo()
      (s1, _) = s0.insert(u.id, u)
    expect AssertionDefect:
      discard s1.insert(u.id, u)

suite "UtxoStore remove":
  test "remove returns the stored Utxo and drops the entry":
    let
      s0 = UtxoStore.init()
      u = mkUtxo()
      (s1, _) = s0.insert(u.id, u)
      r = s1.remove(u.id)
    check r.isOk
    let (s2, removed) = r.get
    check removed == u
    check s2.len == 0
    check not s2.contains(u.id)
    check s2.path(u.id).isNone

  test "remove of absent key returns NotFound":
    let
      s = UtxoStore.init()
      missing = mkUtxo().id
      r = s.remove(missing)
    check r.isErr
    check r.error == UtxoStoreError.NotFound

  test "insert-then-remove returns to empty root":
    var
      s = UtxoStore.init()
      ids = newSeqOfCap[NoteId](10)
    let emptyRoot = s.root
    for i in 0 ..< 10:
      let u = mkUtxo(value = Value(i + 1))
      s = s.insert(u.id, u).store
      ids.add(u.id)

    for id in ids:
      s = s.remove(id).get.store

    check s.root == emptyRoot
    check s.isEmpty

  test "remove + reinsert lands at the freed leaf index":
    var
      s = UtxoStore.init()
      ids = newSeqOfCap[NoteId](3)
    for i in 0 ..< 3:
      let u = mkUtxo(value = Value(i + 1))
      s = s.insert(u.id, u).store
      ids.add(u.id)

    s = s.remove(ids[1]).get.store

    let uNew = mkUtxo(value = 999)
    check s.insert(uNew.id, uNew).leafIndex == 1

suite "UtxoStore utxos() accessor":
  test "exposes the underlying NoteId → (Utxo, leafIndex) map":
    let
      s = UtxoStore.init()
      u = mkUtxo()
      (s1, idx) = s.insert(u.id, u)
      entry = s1.utxos.get(u.id)
    check entry.isSome
    check entry.get.utxo == u
    check entry.get.leafIndex == idx

suite "UtxoStore root determinism / mixed ops":
  test "same insertions on two fresh stores yield equal root":
    var
      a = UtxoStore.init()
      b = UtxoStore.init()
    for i in 0 ..< 50:
      let u = mkUtxo(value = Value(i + 1), pkSeed = byte(i + 1))
      a = a.insert(u.id, u).store
      b = b.insert(u.id, u).store
    check a.root == b.root
    check a == b

  test "interleaved insert / remove / insert preserves size and membership":
    var
      s = UtxoStore.init()
      ids = newSeqOfCap[NoteId](4)
    for i in 0 ..< 4:
      let u = mkUtxo(value = Value(i + 1), pkSeed = byte(i + 1))
      s = s.insert(u.id, u).store
      ids.add(u.id)
    check s.len == 4

    s = s.remove(ids[1]).get.store
    check s.len == 3
    check not s.contains(ids[1])

    s = s.remove(ids[3]).get.store
    check s.len == 2
    check not s.contains(ids[3])

    let uNew = mkUtxo(value = 999, pkSeed = 9)
    s = s.insert(uNew.id, uNew).store
    check s.len == 3
    check s.contains(uNew.id)

{.pop.}
