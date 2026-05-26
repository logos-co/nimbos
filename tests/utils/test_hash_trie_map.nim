# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import std/[hashes, random, sets, strutils, tables]
import unittest2
import results

import ../../logos_chain/utils/hash_trie_map

## A key type whose hash is fully controlled by the caller, so we can force
## collisions and exercise the Collision-node path explicitly.
type CollidingKey = object
  id: int
  bucket: int # used as the hash; equal `bucket` ⇒ hash collision

func hash(x: CollidingKey): Hash =
  Hash(x.bucket)
func `==`(a, b: CollidingKey): bool =
  a.id == b.id

suite "HashTrieMap basics":
  test "init creates empty map":
    let m = HashTrieMap[int, string].init()
    check m.len == 0
    check m.isEmpty
    check 1 notin m
    check m.get(1) == Opt.none(string)
    check m.getOrDefault(1) == ""

  test "insert stores entry; len grows":
    var m = HashTrieMap[int, string].init()
    m = m.insert(1, "one")
    check m.len == 1
    check not m.isEmpty
    check 1 in m
    check m.get(1) == Opt.some("one")
    check m[1] == "one"
    check m.getOrDefault(1) == "one"
    check m.getOrDefault(2, "fallback") == "fallback"

  test "insert with existing key replaces value; len unchanged":
    var m = HashTrieMap[int, string].init()
    m = m.insert(1, "one")
    m = m.insert(1, "uno")
    check m.len == 1
    check m.get(1) == Opt.some("uno")

  test "insert many entries; all retrievable":
    var m = HashTrieMap[int, int].init()
    for i in 0 ..< 1_000:
      m = m.insert(i, i * 7)
    check m.len == 1_000
    for i in 0 ..< 1_000:
      check m.get(i) == Opt.some(i * 7)

  test "remove drops a single entry":
    var m = HashTrieMap[int, string].init()
    m = m.insert(1, "one")
    m = m.insert(2, "two")
    m = m.remove(1)
    check m.len == 1
    check 1 notin m
    check 2 in m
    check m.get(2) == Opt.some("two")

  test "remove of absent key is idempotent":
    var m = HashTrieMap[int, string].init()
    m = m.insert(1, "one")
    let m2 = m.remove(99)
    check m2.len == 1
    check m2.get(1) == Opt.some("one")

  test "insert then remove all empties the map":
    var m = HashTrieMap[int, int].init()
    for i in 0 ..< 100:
      m = m.insert(i, i)
    for i in 0 ..< 100:
      m = m.remove(i)
    check m.len == 0
    check m.isEmpty
    check m == HashTrieMap[int, int].init()

  test "subscript raises KeyError on missing":
    let m = HashTrieMap[int, int].init()
    expect KeyError:
      discard m[42]

  test "getOrDefault returns default(V) when missing":
    let m = HashTrieMap[int, int].init()
    check m.getOrDefault(1) == 0

suite "HashTrieMap withValue":
  test "single-body form runs body only when key is present":
    var m = HashTrieMap[int, int].init()
    m = m.insert(1, 100)

    var found = -1
    m.withValue(1) do(v: int):
      found = v
    check found == 100

    var notFoundRan = false
    m.withValue(99) do(v: int):
      notFoundRan = true
    check not notFoundRan

  test "two-body form covers both branches":
    var m = HashTrieMap[int, int].init()
    m = m.insert(1, 100)

    var
      seenVal = -1
      missingHit = false
    m.withValue(1) do(v: int):
      seenVal = v
    do:
      missingHit = true
    check seenVal == 100
    check not missingHit

    seenVal = -1
    missingHit = false
    m.withValue(99) do(v: int):
      seenVal = v
    do:
      missingHit = true
    check seenVal == -1
    check missingHit

suite "HashTrieMap persistence":
  test "old map unaffected after insert":
    let
      m0 = HashTrieMap[int, int].init()
      m1 = m0.insert(1, 100)
    check m0.len == 0
    check m1.len == 1
    check m0.get(1) == Opt.none(int)
    check m1.get(1) == Opt.some(100)

  test "old map unaffected after remove":
    var m1 = HashTrieMap[int, int].init()
    m1 = m1.insert(1, 100)
    m1 = m1.insert(2, 200)
    let m2 = m1.remove(1)
    check m1.len == 2
    check m2.len == 1
    check m1.get(1) == Opt.some(100)
    check m2.get(1) == Opt.none(int)
    check m1.get(2) == Opt.some(200)
    check m2.get(2) == Opt.some(200)

  test "many versions coexist independently":
    var versions = newSeqOfCap[HashTrieMap[int, int]](201)
    versions.add(HashTrieMap[int, int].init())
    for i in 0 ..< 200:
      versions.add(versions[i].insert(i, i * 3))
    # Each version should contain exactly the keys inserted up to that point.
    for i in 0 ..< versions.len:
      check versions[i].len == i
      for j in 0 ..< i:
        check versions[i].get(j) == Opt.some(j * 3)
      check versions[i].get(i) == Opt.none(int)
      check versions[i].get(i + 9_999) == Opt.none(int)

  test "mutating one version provably leaves the other unchanged":
    var m1 = HashTrieMap[int, int].init()
    for i in 0 ..< 50:
      m1 = m1.insert(i, i * 2)
    let snapshot = m1
    m1 = m1.insert(25, -999) # overwrite
    m1 = m1.remove(40) # delete
    m1 = m1.insert(1000, 1234) # extend
    # Snapshot is untouched by every kind of subsequent mutation.
    check snapshot != m1
    check snapshot.len == 50
    check snapshot.get(25) == Opt.some(50)
    check snapshot.get(40) == Opt.some(80)
    check snapshot.get(1000) == Opt.none(int)
    # And m1 reflects every mutation.
    check m1.len == 50
    check m1.get(25) == Opt.some(-999)
    check m1.get(40) == Opt.none(int)
    check m1.get(1000) == Opt.some(1234)

suite "HashTrieMap collisions":
  test "two keys with same hash and different identity coexist":
    var m = HashTrieMap[CollidingKey, int].init()
    let
      a = CollidingKey(id: 1, bucket: 7)
      b = CollidingKey(id: 2, bucket: 7)
    m = m.insert(a, 100)
    m = m.insert(b, 200)
    check m.len == 2
    check m.get(a) == Opt.some(100)
    check m.get(b) == Opt.some(200)

  test "remove one entry from a 3-way collision":
    var m = HashTrieMap[CollidingKey, int].init()
    let
      a = CollidingKey(id: 1, bucket: 42)
      b = CollidingKey(id: 2, bucket: 42)
      c = CollidingKey(id: 3, bucket: 42)
    m = m.insert(a, 1).insert(b, 2).insert(c, 3)
    check m.len == 3

    m = m.remove(b)
    check m.len == 2
    check m.get(a) == Opt.some(1)
    check m.get(b) == Opt.none(int)
    check m.get(c) == Opt.some(3)

  test "collapsing collision down to one entry leaves survivor accessible":
    var m = HashTrieMap[CollidingKey, int].init()
    let
      a = CollidingKey(id: 1, bucket: 99)
      b = CollidingKey(id: 2, bucket: 99)
    m = m.insert(a, 1).insert(b, 2)
    m = m.remove(a)
    check m.len == 1
    check m.get(a) == Opt.none(int)
    check m.get(b) == Opt.some(2)

  test "insert with different hash splits collision into a branch chain":
    var m = HashTrieMap[CollidingKey, int].init()
    m = m.insert(CollidingKey(id: 1, bucket: 7), 1)
    m = m.insert(CollidingKey(id: 2, bucket: 7), 2)
    # Both above share bucket 7. Add an entry in a different bucket.
    m = m.insert(CollidingKey(id: 3, bucket: 13), 3)
    check m.len == 3
    check m.get(CollidingKey(id: 1, bucket: 7)) == Opt.some(1)
    check m.get(CollidingKey(id: 2, bucket: 7)) == Opt.some(2)
    check m.get(CollidingKey(id: 3, bucket: 13)) == Opt.some(3)

  test "stress: many entries packed into a small number of hash buckets":
    # Forces deep linear search inside Collision nodes by limiting buckets.
    const NumEntries = 10_000
    const NumBuckets = 50
    var m = HashTrieMap[CollidingKey, int].init()
    for i in 0 ..< NumEntries:
      m = m.insert(CollidingKey(id: i, bucket: i mod NumBuckets), i)
    check m.len == NumEntries
    for i in 0 ..< NumEntries:
      check m.get(CollidingKey(id: i, bucket: i mod NumBuckets)) == Opt.some(i)
    # Removing every other entry leaves a still-valid map.
    for i in countup(0, NumEntries - 1, 2):
      m = m.remove(CollidingKey(id: i, bucket: i mod NumBuckets))
    check m.len == NumEntries div 2
    for i in 0 ..< NumEntries:
      let key = CollidingKey(id: i, bucket: i mod NumBuckets)
      if (i and 1) == 0:
        check m.get(key) == Opt.none(int)
      else:
        check m.get(key) == Opt.some(i)

suite "HashTrieMap iteration":
  test "pairs yields every entry exactly once":
    var m = HashTrieMap[int, int].init()
    for i in 0 ..< 200:
      m = m.insert(i, i * 11)
    var
      seen: HashSet[int]
      visited = 0
    for k, v in m.pairs:
      check v == k * 11
      check k notin seen
      seen.incl(k)
      inc visited
    check visited == 200
    check seen.len == 200

  test "keys yields all distinct keys":
    var m = HashTrieMap[int, int].init()
    for i in 0 ..< 50:
      m = m.insert(i, i)
    var seen: HashSet[int]
    for k in m.keys:
      seen.incl(k)
    check seen.len == 50

  test "values yields all values (with multiplicity)":
    var m = HashTrieMap[int, int].init()
    for i in 0 ..< 50:
      m = m.insert(i, i mod 3)
    var total = 0
    for v in m.values:
      total += v
    var expectedTotal = 0
    for i in 0 ..< 50:
      expectedTotal += i mod 3
    check total == expectedTotal

  test "iteration on empty map yields nothing":
    let m = HashTrieMap[int, int].init()
    var ran = false
    for _, _ in m.pairs:
      ran = true
    check not ran

  test "iteration covers collision buckets":
    var m = HashTrieMap[CollidingKey, int].init()
    m = m.insert(CollidingKey(id: 1, bucket: 7), 10)
    m = m.insert(CollidingKey(id: 2, bucket: 7), 20)
    m = m.insert(CollidingKey(id: 3, bucket: 13), 30)
    var seen: HashSet[int]
    for k, v in m.pairs:
      seen.incl(v)
    check seen == toHashSet([10, 20, 30])

  test "iteration order is deterministic for the same insert sequence":
    # Order is unspecified by contract, but it must be a pure function of
    # the resulting tree shape — two maps built the same way must traverse
    # identically. This is what makes ``$`` and pairs-based hashing usable.
    var
      a = HashTrieMap[int, int].init()
      b = HashTrieMap[int, int].init()
    for i in 0 ..< 150:
      a = a.insert(i, i * 3)
      b = b.insert(i, i * 3)
    var
      aOrder = newSeqOfCap[int](a.len)
      bOrder = newSeqOfCap[int](b.len)
    for k, v in a.pairs:
      aOrder.add(k)
    for k, v in b.pairs:
      bOrder.add(k)
    check aOrder == bOrder

  test "iteration covers exactly the current key set after random churn":
    var
      rng = initRand(0xDEADBEEF_5678)
      m = HashTrieMap[int, int].init()
      t = initTable[int, int]()
    for _ in 0 ..< 3_000:
      let k = rng.rand(0 .. 99)
      if rng.rand(1) == 0:
        let v = rng.rand(0 .. 1_000)
        m = m.insert(k, v)
        t[k] = v
      else:
        m = m.remove(k)
        t.del(k)
    var keys: HashSet[int]
    for k, v in m.pairs:
      check t.hasKey(k)
      check t[k] == v
      keys.incl(k)
    check keys.len == t.len

suite "HashTrieMap equality":
  test "empty maps are equal":
    let
      a = HashTrieMap[int, int].init()
      b = HashTrieMap[int, int].init()
    check a == b

  test "same content, same insertion order":
    var
      a = HashTrieMap[int, int].init()
      b = HashTrieMap[int, int].init()
    for i in 0 ..< 100:
      a = a.insert(i, i * 2)
      b = b.insert(i, i * 2)
    check a == b

  test "same content, different insertion order":
    var
      a = HashTrieMap[int, int].init()
      b = HashTrieMap[int, int].init()
    for i in 0 ..< 50:
      a = a.insert(i, i)
    for i in countdown(49, 0):
      b = b.insert(i, i)
    check a == b

  test "different lengths are unequal":
    var a = HashTrieMap[int, int].init()
    a = a.insert(1, 1)
    let b = HashTrieMap[int, int].init()
    check a != b

  test "same keys, different values are unequal":
    var
      a = HashTrieMap[int, int].init()
      b = HashTrieMap[int, int].init()
    a = a.insert(1, 100)
    b = b.insert(1, 200)
    check a != b

  test "remove restores equality":
    var
      a = HashTrieMap[int, int].init()
      b = HashTrieMap[int, int].init()
    a = a.insert(1, 1).insert(2, 2)
    b = b.insert(1, 1).insert(2, 2).insert(99, 99)
    check a != b
    b = b.remove(99)
    check a == b

suite "HashTrieMap $":
  test "empty map stringifies to {}":
    let m = HashTrieMap[int, int].init()
    check $m == "{}"

  test "single-entry map":
    var m = HashTrieMap[int, string].init()
    m = m.insert(1, "one")
    check $m == "{1: one}"

  test "multi-entry contains all (key, value) pairs":
    var m = HashTrieMap[int, int].init()
    for i in 0 ..< 5:
      m = m.insert(i, i * 10)
    let s = $m
    for i in 0 ..< 5:
      check ($i & ": " & $(i * 10)) in s

suite "HashTrieMap fuzz":
  test "behaves like std/tables.Table under random insert/remove":
    var
      rng = initRand(0xC0FFEE_1234)
      m = HashTrieMap[int, int].init()
      t = initTable[int, int]()

    for _ in 0 ..< 5_000:
      let
        op = rng.rand(2)
        k = rng.rand(0 .. 199)
      case op
      of 0:
        # Insert
        let v = rng.rand(0 .. 1_000_000)
        m = m.insert(k, v)
        t[k] = v
      of 1:
        # Remove
        m = m.remove(k)
        t.del(k)
      else:
        # Read-check
        check m.contains(k) == t.hasKey(k)
        if t.hasKey(k):
          check m.get(k) == Opt.some(t[k])
          check m[k] == t[k]
        else:
          check m.get(k) == Opt.none(int)

    # Cross-check final state.
    check m.len == t.len
    var collected: HashSet[int]
    for k, v in m.pairs:
      check t[k] == v
      collected.incl(k)
    check collected.len == t.len

suite "HashTrieMap diverse types":
  test "string keys":
    var m = HashTrieMap[string, int].init()
    m = m.insert("alpha", 1)
    m = m.insert("beta", 2)
    m = m.insert("gamma", 3)
    m = m.insert("beta", 20) # overwrite
    check m.len == 3
    check m["alpha"] == 1
    check m["beta"] == 20
    check m["gamma"] == 3
    check m.get("delta") == Opt.none(int)

  test "seq[byte] keys":
    var m = HashTrieMap[seq[byte], int].init()
    let
      k1 = @[0x01'u8, 0x02, 0x03]
      k2 = @[0x04'u8, 0x05]
      k3 = @[0x01'u8, 0x02, 0x03, 0x04] # k1 prefix
    m = m.insert(k1, 1)
    m = m.insert(k2, 2)
    m = m.insert(k3, 3)
    check m.len == 3
    check m[k1] == 1
    check m[k2] == 2
    check m[k3] == 3
    # k1 prefix doesn't accidentally hit k3
    check m.get(@[0x01'u8, 0x02]) == Opt.none(int)

  test "object values":
    type Point = object
      x, y: int

    var m = HashTrieMap[int, Point].init()
    m = m.insert(1, Point(x: 10, y: 20))
    m = m.insert(2, Point(x: -1, y: -2))
    check m.len == 2
    check m[1] == Point(x: 10, y: 20)
    check m[2] == Point(x: -1, y: -2)
    # Reading a copy out and mutating it must not touch the stored value.
    var localCopy = m[1]
    localCopy.x = 999
    check m[1] == Point(x: 10, y: 20)

suite "HashTrieMap scale and structure":
  test "10k entries: full insert / lookup / iterate / remove cycle":
    const N = 10_000
    var m = HashTrieMap[int, int].init()
    for i in 0 ..< N:
      m = m.insert(i, i * 3)
    check m.len == N
    for i in 0 ..< N:
      check m[i] == i * 3
    var
      visited = 0
      sum = 0
    for k, v in m.pairs:
      inc visited
      sum += k
    check visited == N
    var expectedSum = 0
    for i in 0 ..< N:
      expectedSum += i
    check sum == expectedSum
    for i in 0 ..< N:
      m = m.remove(i)
    check m.isEmpty

  test "32 distinct slot-0 hashes fill a root branch (all children occupied)":
    # Buckets 0..31 produce Hash values 0..31, whose low-5-bit slots are
    # 0..31 respectively — each gets its own leaf directly under the root
    # branch. This exercises a fully-populated 32-way Branch node.
    var m = HashTrieMap[CollidingKey, int].init()
    for i in 0 ..< BranchCount:
      m = m.insert(CollidingKey(id: i, bucket: i), i * 100)
    check m.len == BranchCount
    for i in 0 ..< BranchCount:
      check m[CollidingKey(id: i, bucket: i)] == i * 100
    var visited = 0
    for k, v in m.pairs:
      inc visited
    check visited == BranchCount

  test "remove then reinsert yields a map equal to original":
    var m = HashTrieMap[int, int].init()
    for i in 0 ..< 200:
      m = m.insert(i, i * 7)
    let original = m
    # Tear out a contiguous range and a scattered set, then rebuild.
    for i in 50 ..< 60:
      m = m.remove(i)
    m = m.remove(0).remove(199).remove(123)
    check m != original
    for i in 50 ..< 60:
      m = m.insert(i, i * 7)
    m = m.insert(0, 0).insert(199, 199 * 7).insert(123, 123 * 7)
    check m == original

suite "HashTrieMap toHashTrieMap":
  test "builds from a table-literal of pairs":
    let m = toHashTrieMap({"a": 1, "b": 2, "c": 3})
    check m.len == 3
    check m["a"] == 1
    check m["b"] == 2
    check m["c"] == 3

  test "duplicate keys: last value wins":
    let m = toHashTrieMap({1: "first", 2: "two", 1: "second", 1: "third"})
    check m.len == 2
    check m[1] == "third"
    check m[2] == "two"

  test "empty input yields an empty map":
    let
      pairs: array[0, tuple[key: int, val: int]] = []
      m = toHashTrieMap(pairs)
    check m.isEmpty
    check m == HashTrieMap[int, int].init()

{.pop.}
