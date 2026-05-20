# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import std/options

import unittest2
import results
import poseidon2/[types, io]

import ../../logos_chain/utils/dynamic_merkle_tree
import ../../logos_chain/zk/poseidon2/hasher # Poseidon2Hasher

# A trivial Item whose `asField` view is its own F value. Exercises the
# `mixin asField(item: Item): F` contract.
type FItem = object
  v: F

func asField(item: FItem): F =
  item.v

func frFomInt(n: int): F =
  ## Deterministic small F from an int — for stable test vectors.
  var bytes: array[32, byte]
  for i in 0 ..< 8:
    bytes[i] = byte((n shr (i * 8)) and 0xff)
  F.fromBytes(bytes).get

suite "DynamicMerkleTree empty":
  test "fresh tree has empty root":
    let t = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
    check t.len == 0
    check t.isEmpty
    check t.capacity == Capacity
    check t.path(0) == Opt.none(MerklePath)

  test "empty trees are equal":
    let
      a = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
      b = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
    check a == b

  test "empty root equals emptySubtreeRoot(TreeDepth)":
    let
      t = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
      er = Poseidon2Hasher.getEmptyRoots()
    check t.root == er[TreeDepth]

suite "DynamicMerkleTree insert / path / verify":
  test "single insert assigns index 0 and produces a valid path":
    let
      t0 = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
      item = FItem(v: frFomInt(42))
      (t1, idx) = t0.insert(item)
    check idx == 0
    check t1.len == 1
    let p = t1.path(0)
    check p.isSome
    check Poseidon2Hasher.verifyPath(p.get, asField(item), t1.root)

  test "many inserts: every leaf has a verifying path":
    var
      t = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
      items = newSeqOfCap[FItem](100)
    for i in 0 ..< 100:
      let
        item = FItem(v: frFomInt(i + 1))
        (t2, idx) = t.insert(item)
      check idx == i
      items.add(item)
      t = t2
    check t.len == 100
    for i in 0 ..< 100:
      let p = t.path(i)
      check p.isSome
      check Poseidon2Hasher.verifyPath(p.get, asField(items[i]), t.root)

  test "persistence: parent tree unchanged by child insert":
    let
      t0 = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
      r0 = t0.root
      (t1, _) = t0.insert(FItem(v: frFomInt(7)))
    check t0.root == r0
    check t0.len == 0
    check t1.root != r0
    check t1.len == 1

  test "deterministic root: same inserts in two fresh trees → equal roots":
    var
      a = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
      b = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
    for i in 0 ..< 20:
      let item = FItem(v: frFomInt(i + 1))
      a = a.insert(item).tree
      b = b.insert(item).tree
    check a.root == b.root
    check a == b

  test "single-item path: every sibling is (Right, emptySubtreeRoot[h])":
    let
      t0 = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
      item = FItem(v: frFomInt(42))
      (t1, _) = t0.insert(item)
      p = t1.path(0).get
      er = Poseidon2Hasher.getEmptyRoots()
    for h in 0 ..< TreeDepth:
      check p[h].side == Right
      check p[h].sibling == er[h]

  test "two-item path: adjacent leaves carry each other's digest at level 0":
    let
      t0 = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
      item0 = FItem(v: frFomInt(10))
      item1 = FItem(v: frFomInt(20))
    let
      (t1, _) = t0.insert(item0)
      (t2, _) = t1.insert(item1)
      p0 = t2.path(0).get
      p1 = t2.path(1).get
    # idx 0 is a left child at the leaf level → its sibling sits on the Right
    # and carries the digest of item1.
    check p0[0].side == Right
    check p0[0].sibling == asField(item1)
    # idx 1 is a right child → sibling on the Left carrying asField(item0).
    check p1[0].side == Left
    check p1[0].sibling == asField(item0)
    # Both verify against the same root.
    check Poseidon2Hasher.verifyPath(p0, asField(item0), t2.root)
    check Poseidon2Hasher.verifyPath(p1, asField(item1), t2.root)

  test "persistence: parent tree unchanged by child remove":
    let
      t = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
      (t1, _) = t.insert(FItem(v: frFomInt(5)))
      r1 = t1.root
      t2 = t1.remove(0)
    check t1.root == r1
    check t1.len == 1
    check t2.len == 0
    check t1.path(0).isSome
    check t2.path(0).isNone

suite "DynamicMerkleTree remove + hole reuse (smallest-first)":
  test "remove nulls the leaf and drops len":
    let
      t = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
      (t1, _) = t.insert(FItem(v: frFomInt(1)))
      t2 = t1.remove(0)
    check t2.len == 0
    check t2.path(0) == Opt.none(MerklePath)
    # Root differs from initial empty-tree root only by the hole bookkeeping
    # — the leaf array is the same all-empty state, so the root must match.
    check t2.root == DynamicMerkleTree[FItem, Poseidon2Hasher].init().root

  test "smallest hole first: next insert lands at the smallest free index":
    var t = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
    for i in 0 ..< 5:
      let (t2, idx) = t.insert(FItem(v: frFomInt(i + 10)))
      check idx == i
      t = t2
    # Remove 3, 1, 4 — Rust-compatible min-heap should hand them back as 1, 3, 4.
    t = t.remove(3)
    t = t.remove(1)
    t = t.remove(4)
    let (t3, first) = t.insert(FItem(v: frFomInt(97)))
    check first == 1
    let (t4, second) = t3.insert(FItem(v: frFomInt(98)))
    check second == 3
    let (_, third) = t4.insert(FItem(v: frFomInt(99)))
    check third == 4

  test "insert-all then remove-all returns to empty-tree root":
    var t = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
    let empty = t.root
    for i in 0 ..< 20:
      let (t2, _) = t.insert(FItem(v: frFomInt(i + 1)))
      t = t2
    for i in 0 ..< 20:
      t = t.remove(i)
    check t.root == empty

  test "root consistency: remove + reinsert same item at same index = same root":
    let
      t0 = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
      item = FItem(v: frFomInt(7))
      (t1, _) = t0.insert(item)
      originalRoot = t1.root
      t2 = t1.remove(0)
      (t3, idx) = t2.insert(item)
    check idx == 0
    check t3.root == originalRoot

  test "remove out of bounds panics":
    let t = DynamicMerkleTree[FItem, Poseidon2Hasher].init()
    expect AssertionDefect:
      discard t.remove(Capacity)
    expect AssertionDefect:
      discard t.remove(-1)

{.pop.}
