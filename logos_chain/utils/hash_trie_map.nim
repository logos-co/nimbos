# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Persistent hash map (Hash Array Mapped Trie). Mutations return a new map
## sharing structure with the old; the old map remains valid. API shape
## mirrors ``std/tables.Table``.
##
## Algorithm: Phil Bagwell, *"Ideal Hash Trees"* (2001).

{.push raises: [], gcsafe.}

import std/[bitops, hashes]
import results

const
  BranchBits* = 5
    ## Bits of hash consumed per trie level. 5 ⇒ 32-way branching.
  BranchCount* = 1 shl BranchBits
    ## Slots per branch node (= 32).
  MaxDepth* =
    (sizeof(Hash) * 8 + BranchBits - 1) div BranchBits
    ## Past this depth, same-hash entries share a ``Collision`` node.

type
  NodeKind {.pure.} = enum
    Branch, Leaf, Collision

  Node[K, V] = ref object
    case kind: NodeKind
    of Branch:
      bitmap: uint32                        # len(children) == popcount(bitmap)
      children: seq[Node[K, V]]
    of Leaf:
      leafHash: Hash
      leafKey: K
      leafValue: V
    of Collision:
      collisionHash: Hash
      entries: seq[tuple[key: K, val: V]]

  HashTrieMap*[K, V] = object
    ## Persistent hash map.
    root: Node[K, V]
    count: int

func hashSlot(h: Hash; depth: int): int =
  # Cast to uint so the shift is logical, not arithmetic.
  let bits = cast[uint](h) shr (depth * BranchBits)
  int(bits and uint(BranchCount - 1))

func bitmapHas(bm: uint32; slot: int): bool =
  (bm and (1'u32 shl slot)) != 0'u32

func bitmapIndex(bm: uint32; slot: int): int =
  countSetBits(bm and ((1'u32 shl slot) - 1'u32))

func init*[K, V](T: typedesc[HashTrieMap[K, V]]): HashTrieMap[K, V] =
  ## Returns an empty map.
  runnableExamples:
    let m = HashTrieMap[string, int].init()
    doAssert m.len == 0
    doAssert m.isEmpty
  HashTrieMap[K, V](root: nil, count: 0)

func len*[K, V](m: HashTrieMap[K, V]): int =
  ## Number of entries. O(1).
  m.count

func isEmpty*[K, V](m: HashTrieMap[K, V]): bool =
  ## True iff ``len(m) == 0``.
  m.count == 0

func findEntry[K, V](
    node: Node[K, V]; h: Hash; k: K; depth: int
): ptr V =
  # Returns a borrowed pointer into ``node``; ``nil`` on miss.
  if node == nil:
    return nil
  case node.kind
  of Leaf:
    if node.leafHash == h and node.leafKey == k:
      addr node.leafValue
    else:
      nil
  of Collision:
    if node.collisionHash != h:
      return nil
    for i in 0 ..< node.entries.len:
      if node.entries[i].key == k:
        return addr node.entries[i].val
    nil
  of Branch:
    let slot = hashSlot(h, depth)
    if not node.bitmap.bitmapHas(slot):
      nil
    else:
      findEntry(node.children[node.bitmap.bitmapIndex(slot)], h, k, depth + 1)

func contains*[K, V](m: HashTrieMap[K, V]; k: K): bool =
  ## True iff key ``k`` has an associated value.
  runnableExamples:
    var m = HashTrieMap[int, string].init()
    m = m.insert(1, "one")
    doAssert 1 in m
    doAssert 2 notin m
  findEntry(m.root, hash(k), k, depth = 0) != nil

func `[]`*[K, V](m: HashTrieMap[K, V]; k: K): lent V {.raises: [KeyError].} =
  ## Retrieves the value at ``m[k]``. Raises ``KeyError`` if ``k`` is absent.
  runnableExamples:
    var m = HashTrieMap[int, string].init()
    m = m.insert(1, "one")
    doAssert m[1] == "one"
    doAssertRaises(KeyError):
      discard m[2]
  let p = findEntry(m.root, hash(k), k, depth = 0)
  if p == nil:
    raise newException(KeyError, "key not in HashTrieMap")
  p[]

func getOrDefault*[K, V](m: HashTrieMap[K, V]; k: K): V =
  ## Retrieves the value at ``m[k]``, or ``default(V)`` if absent.
  runnableExamples:
    var m = HashTrieMap[string, int].init()
    m = m.insert("x", 42)
    doAssert m.getOrDefault("x") == 42
    doAssert m.getOrDefault("y") == 0
  let p = findEntry(m.root, hash(k), k, depth = 0)
  if p == nil:
    default(V)
  else:
    p[]

func getOrDefault*[K, V](m: HashTrieMap[K, V]; k: K; fallback: V): V =
  ## Retrieves the value at ``m[k]``, or ``fallback`` if absent.
  let p = findEntry(m.root, hash(k), k, depth = 0)
  if p == nil:
    fallback
  else:
    p[]

# ``withValue`` is closure-based, not template-based (unlike std/tables):
# a template would expose ``ptr V``, letting callers write through it and
# silently mutate Leaf nodes shared with other map versions — breaking
# persistence. Closure parameters are immutable by default, enforcing
# read-only at compile time. Tradeoff: one indirect call per invocation.

proc withValue*[K, V](
    m: HashTrieMap[K, V]; k: K;
    onFound: proc(v: V) {.gcsafe, raises: [].}) =
  ## Calls ``onFound`` with the value at ``k`` if present, else does nothing.
  let p = findEntry(m.root, hash(k), k, depth = 0)
  if p != nil:
    onFound(p[])

proc withValue*[K, V](
    m: HashTrieMap[K, V]; k: K;
    onFound: proc(v: V) {.gcsafe, raises: [].};
    notFound: proc() {.gcsafe, raises: [].}) =
  ## Two-branch form: ``notFound`` runs when ``k`` is absent.
  let p = findEntry(m.root, hash(k), k, depth = 0)
  if p != nil:
    onFound(p[])
  else:
    notFound()

func get*[K, V](m: HashTrieMap[K, V]; k: K): Opt[V] =
  ## Returns ``Opt.some(value)`` if ``k`` is present, ``Opt.none(V)`` otherwise.
  runnableExamples:
    var m = HashTrieMap[int, int].init()
    m = m.insert(1, 100)
    doAssert m.get(1) == Opt.some(100)
    doAssert m.get(2) == Opt.none(int)
  let p = findEntry(m.root, hash(k), k, depth = 0)
  if p == nil:
    Opt.none(V)
  else:
    Opt.some(p[])

func makeBranchFromTwoNodes[K, V](
    a, b: Node[K, V]; depth: int
): Node[K, V] =
  # Precondition: ``a`` and ``b`` have different full hashes (otherwise
  # the right representation is a ``Collision`` node, not a Branch).
  doAssert depth < MaxDepth,
    "HashTrieMap: branch nesting exceeded max depth — same-hash entries " &
    "must route through a Collision node, not a Branch chain"

  let
    aHash = (if a.kind == Leaf: a.leafHash else: a.collisionHash)
    bHash = (if b.kind == Leaf: b.leafHash else: b.collisionHash)
    slotA = hashSlot(aHash, depth)
    slotB = hashSlot(bHash, depth)

  if slotA == slotB:
    # Both share this depth's slot — nest deeper.
    Node[K, V](
      kind: Branch,
      bitmap: 1'u32 shl slotA,
      children: @[makeBranchFromTwoNodes(a, b, depth + 1)])
  else:
    let
      bm = (1'u32 shl slotA) or (1'u32 shl slotB)
      children =
        if slotA < slotB: @[a, b]
        else:             @[b, a]
    Node[K, V](kind: Branch, bitmap: bm, children: children)

proc insertNode[K, V](
    node: Node[K, V]; h: Hash; k: K; v: sink V; depth: int;
    added: var bool
): Node[K, V] =
  # ``added`` is set true iff a new entry was created (vs. replacing).
  if node == nil:
    added = true
    return Node[K, V](kind: Leaf, leafHash: h, leafKey: k, leafValue: v)

  case node.kind
  of Leaf:
    if node.leafHash == h:
      if node.leafKey == k:
        added = false
        return Node[K, V](kind: Leaf, leafHash: h, leafKey: k, leafValue: v)
      added = true
      return Node[K, V](
        kind: Collision,
        collisionHash: h,
        entries: @[(node.leafKey, node.leafValue), (k, v)])
    added = true
    makeBranchFromTwoNodes(
      node,
      Node[K, V](kind: Leaf, leafHash: h, leafKey: k, leafValue: v),
      depth)

  of Collision:
    if node.collisionHash == h:
      for i in 0 ..< node.entries.len:
        if node.entries[i].key == k:
          added = false
          var newEntries = node.entries
          newEntries[i] = (k, v)
          return Node[K, V](
            kind: Collision, collisionHash: h, entries: newEntries)
      added = true
      var newEntries = node.entries
      newEntries.add((k, v))
      return Node[K, V](
        kind: Collision, collisionHash: h, entries: newEntries)
    added = true
    makeBranchFromTwoNodes(
      node,
      Node[K, V](kind: Leaf, leafHash: h, leafKey: k, leafValue: v),
      depth)

  of Branch:
    let slot = hashSlot(h, depth)
    if not node.bitmap.bitmapHas(slot):
      added = true
      let idx = node.bitmap.bitmapIndex(slot)
      var newChildren = newSeq[Node[K, V]](node.children.len + 1)
      for i in 0 ..< idx:
        newChildren[i] = node.children[i]
      newChildren[idx] = Node[K, V](
        kind: Leaf, leafHash: h, leafKey: k, leafValue: v)
      for i in idx ..< node.children.len:
        newChildren[i + 1] = node.children[i]
      return Node[K, V](
        kind: Branch,
        bitmap: node.bitmap or (1'u32 shl slot),
        children: newChildren)
    let idx = node.bitmap.bitmapIndex(slot)
    # Path-copying: copy this Branch's children seq so the old node stays
    # immutable; sibling subtrees stay shared via the seq's element refs.
    var newChildren = node.children
    newChildren[idx] = insertNode(node.children[idx], h, k, v, depth + 1, added)
    Node[K, V](
      kind: Branch, bitmap: node.bitmap, children: newChildren)

func insert*[K, V](m: HashTrieMap[K, V]; k: K; v: sink V): HashTrieMap[K, V] =
  ## Returns a new map with ``(k, v)`` inserted. Replaces an existing value
  ## for ``k``. O(log32 n).
  runnableExamples:
    var m = HashTrieMap[int, string].init()
    m = m.insert(1, "one")
    m = m.insert(2, "two")
    doAssert m.len == 2
    doAssert m.get(1) == Opt.some("one")
  var added = false
  let newRoot = insertNode(m.root, hash(k), k, v, depth = 0, added = added)
  HashTrieMap[K, V](
    root: newRoot,
    count: m.count + (if added: 1 else: 0))

proc removeNode[K, V](
    node: Node[K, V]; h: Hash; k: K; depth: int;
    removed: var bool
): Node[K, V] =
  # Returns the new subtree (or ``nil`` if empty). ``removed`` is set iff
  # the key was actually present.
  if node == nil:
    removed = false
    return nil

  case node.kind
  of Leaf:
    if node.leafHash == h and node.leafKey == k:
      removed = true
      return nil
    removed = false
    return node

  of Collision:
    if node.collisionHash != h:
      removed = false
      return node
    var found = -1
    for i in 0 ..< node.entries.len:
      if node.entries[i].key == k:
        found = i
        break
    if found < 0:
      removed = false
      return node
    removed = true
    if node.entries.len == 2:
      # Collapse the collision bucket back to a single Leaf.
      let surviving = node.entries[1 - found]
      return Node[K, V](
        kind: Leaf, leafHash: h, leafKey: surviving.key, leafValue: surviving.val)
    var newEntries = node.entries
    newEntries.delete(found)
    Node[K, V](kind: Collision, collisionHash: h, entries: newEntries)

  of Branch:
    let slot = hashSlot(h, depth)
    if not node.bitmap.bitmapHas(slot):
      removed = false
      return node
    let
      idx = node.bitmap.bitmapIndex(slot)
      newChild = removeNode(node.children[idx], h, k, depth + 1, removed)
    if not removed:
      return node

    if newChild == nil:
      let newBitmap = node.bitmap and not (1'u32 shl slot)
      if newBitmap == 0'u32:
        return nil
      var newChildren = newSeq[Node[K, V]](node.children.len - 1)
      for i in 0 ..< idx:
        newChildren[i] = node.children[i]
      for i in idx + 1 ..< node.children.len:
        newChildren[i - 1] = node.children[i]
      # Compress single-Leaf branches up one level. Don't collapse Collision
      # children — they may need to expand again on further inserts here.
      if newChildren.len == 1 and newChildren[0].kind == Leaf:
        return newChildren[0]
      return Node[K, V](
        kind: Branch, bitmap: newBitmap, children: newChildren)

    var newChildren = node.children
    newChildren[idx] = newChild
    Node[K, V](
      kind: Branch, bitmap: node.bitmap, children: newChildren)

func remove*[K, V](m: HashTrieMap[K, V]; k: K): HashTrieMap[K, V] =
  ## Returns a new map with ``k`` removed. No-op (shares the root) if absent.
  ## O(log32 n).
  runnableExamples:
    var m = HashTrieMap[int, string].init()
    m = m.insert(1, "one")
    m = m.remove(1)
    doAssert m.isEmpty
    doAssert m.remove(99).len == 0
  var removed = false
  let newRoot = removeNode(m.root, hash(k), k, depth = 0, removed = removed)
  HashTrieMap[K, V](
    root: newRoot,
    count: m.count - (if removed: 1 else: 0))

iterator pairs*[K, V](m: HashTrieMap[K, V]): tuple[key: K, val: V] =
  ## Yields all ``(key, value)`` entries. Order is unspecified.
  if m.root != nil:
    var stack: seq[Node[K, V]] = @[m.root]
    while stack.len > 0:
      let n = stack.pop()
      case n.kind
      of Leaf:
        yield (n.leafKey, n.leafValue)
      of Collision:
        for entry in n.entries:
          yield (entry.key, entry.val)
      of Branch:
        # Reverse-push so the lowest slot is yielded first.
        for i in countdown(n.children.len - 1, 0):
          stack.add(n.children[i])

iterator keys*[K, V](m: HashTrieMap[K, V]): lent K =
  ## Yields all keys, zero-copy. Order is unspecified.
  if m.root != nil:
    var stack: seq[Node[K, V]] = @[m.root]
    while stack.len > 0:
      let n = stack.pop()
      case n.kind
      of Leaf:
        yield n.leafKey
      of Collision:
        for entry in n.entries:
          yield entry.key
      of Branch:
        for i in countdown(n.children.len - 1, 0):
          stack.add(n.children[i])

iterator values*[K, V](m: HashTrieMap[K, V]): lent V =
  ## Yields all values, zero-copy. Order is unspecified.
  if m.root != nil:
    var stack: seq[Node[K, V]] = @[m.root]
    while stack.len > 0:
      let n = stack.pop()
      case n.kind
      of Leaf:
        yield n.leafValue
      of Collision:
        for entry in n.entries:
          yield entry.val
      of Branch:
        for i in countdown(n.children.len - 1, 0):
          stack.add(n.children[i])

func `==`*[K, V](a, b: HashTrieMap[K, V]): bool =
  ## Structural equality: same key set, same value per key. O(n).
  runnableExamples:
    var
      a = HashTrieMap[int, int].init()
      b = HashTrieMap[int, int].init()
    a = a.insert(1, 10).insert(2, 20)
    b = b.insert(2, 20).insert(1, 10)
    doAssert a == b
  if a.count != b.count:
    return false
  for (k, v) in a.pairs:
    let pb = findEntry(b.root, hash(k), k, depth = 0)
    if pb == nil or pb[] != v:
      return false
  true

func toHashTrieMap*[K, V](
    pairs: openArray[tuple[key: K, val: V]]): HashTrieMap[K, V] =
  ## Builds a map from ``(key, value)`` pairs. Duplicate keys keep the last value.
  runnableExamples:
    let m = toHashTrieMap({"a": 1, "b": 2, "c": 3})
    doAssert m.len == 3
    doAssert m["b"] == 2
  result = HashTrieMap[K, V].init()
  for (k, v) in pairs:
    result = result.insert(k, v)

func `$`*[K, V](m: HashTrieMap[K, V]): string =
  ## Returns a ``{k: v, ...}`` string. Order is unspecified.
  runnableExamples:
    var m = HashTrieMap[int, string].init()
    m = m.insert(1, "one")
    doAssert "1: one" in $m
  result = "{"
  var first = true
  for (k, v) in m.pairs:
    if not first: result.add(", ")
    first = false
    result.add($k & ": " & $v)
  result.add("}")

{.pop.}
