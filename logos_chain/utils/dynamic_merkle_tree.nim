# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

# Persistent fixed-depth Merkle tree (Hash Array Mapped Trie equivalent for
# index-addressed leaves). Mutations return a new tree sharing structure with
# the old; the old tree remains valid.
# Hash: Poseidon2 over BN254 ``Fr`` via ``logos_chain/zk/poseidon2/hasher``.

{.push raises: [], gcsafe.}

import std/[heapqueue, options, strutils]
import results

import poseidon2/types        # F = Fr[BN254_Snarks], zero
import constantine/math/io/io_fields  # toHex on F

export F  # transitive re-export for callers

const
  TreeDepth* = 32
  Capacity*  = 1 shl TreeDepth   # 2^32 leaves

type
  Side* {.pure.} = enum
    Left   # sibling on the left 
    Right  # sibling on the right

  MerkleNode* = object
    side*: Side
    sibling*: F

  MerklePath* = array[TreeDepth, MerkleNode]
    ## Inclusion proof: 32 tagged siblings, leaf → root order, root excluded.
    ## Wire format (when standardised) is ``u8 side || Fr sibling`` per node.

  NodeKind {.pure.} = enum
    Inner, Empty, Leaf

  Node[Item, Hash] = ref object
    case kind: NodeKind
    of Inner:
      left, right: Node[Item, Hash]
      value: F
      leftSize, rightSize: int
      height: int           # 1..TreeDepth
    of Empty:
      eHeight: int          # valid only as right-of-Inner or as root
    of Leaf:
      item: Option[Item]

  DynamicMerkleTree*[Item, Hash] = object
    ## Persistent fixed-depth Merkle tree. Capacity = 2^TreeDepth.
    ## ``Hash`` is a typedesc with a ``compress(_: type Hash, a, b: F): F`` proc
    ## in scope (same idiom as nimcrypto's ``HMAC[HashType]``).
    root: Node[Item, Hash]
    holes: HeapQueue[int]   # min-heap; smallest-free-index returned first
    count: int

# Per-Hash lazy cache of empty subtree roots for heights 0..TreeDepth.
# `const` doesn't work — constantine's Fr arithmetic isn't VM-evaluable.
# Each `Hash` instantiation gets its own `{.global.}` cache, filled once.
proc getEmptyRoots*(Hash: typedesc): array[TreeDepth + 1, F] {.gcsafe.} =
  mixin compress
  {.cast(gcsafe).}:
    var
      cache {.global.}: array[TreeDepth + 1, F]
      inited {.global.} = false
    if not inited:
      cache[0] = zero
      for h in 1 .. TreeDepth:
        cache[h] = Hash.compress(cache[h - 1], cache[h - 1])
      inited = true
    cache

func emptySubtreeRoot(Hash: typedesc; height: int): F =
  doAssert height in 0 .. TreeDepth, "height " & $height & " out of range"
  {.cast(noSideEffect).}:
    Hash.getEmptyRoots()[height]

func nodeHeight[Item, Hash](n: Node[Item, Hash]): int =
  case n.kind
  of Inner: n.height
  of Empty: n.eHeight
  of Leaf:  0

func nodeSize[Item, Hash](n: Node[Item, Hash]): int =
  case n.kind
  of Inner: n.leftSize + n.rightSize
  of Empty: 0
  of Leaf:  (if n.item.isSome: 1 else: 0)

func nodeCapacity[Item, Hash](n: Node[Item, Hash]): int =
  1 shl nodeHeight(n)

func value[Item, Hash](n: Node[Item, Hash]): F =
  mixin asField
  case n.kind
  of Inner: n.value
  of Empty: Hash.emptySubtreeRoot(n.eHeight)
  of Leaf:
    if n.item.isSome: asField(n.item.get)
    else: zero

func newInner[Item, Hash](left, right: Node[Item, Hash]): Node[Item, Hash] =
  mixin compress
  doAssert left.kind != Empty,
    "Empty allowed only on the right; left was Empty"
  Node[Item, Hash](
    kind: Inner,
    left: left,
    right: right,
    value: Hash.compress(value(left), value(right)),
    leftSize: nodeSize(left),
    rightSize: nodeSize(right),
    height: max(nodeHeight(left), nodeHeight(right)) + 1)

func init*[Item, Hash](_: typedesc[DynamicMerkleTree[Item, Hash]]): DynamicMerkleTree[Item, Hash] =
  ## Empty tree; ``root`` = ``emptySubtreeRoot(TreeDepth)``.
  DynamicMerkleTree[Item, Hash](
    root: Node[Item, Hash](kind: Empty, eHeight: TreeDepth),
    holes: initHeapQueue[int](),
    count: 0)

func len*[Item, Hash](t: DynamicMerkleTree[Item, Hash]): int =
  ## Populated leaf count (excluding holes).
  t.count

func capacity*[Item, Hash](t: DynamicMerkleTree[Item, Hash]): int =
  Capacity

func isEmpty*[Item, Hash](t: DynamicMerkleTree[Item, Hash]): bool =
  t.count == 0

func root*[Item, Hash](t: DynamicMerkleTree[Item, Hash]): F =
  value(t.root)

func modifyAt[Item, Hash](
    n: Node[Item, Hash]; index: int;
    f: proc(leaf: Node[Item, Hash]): Node[Item, Hash] {.gcsafe, raises: [], noSideEffect.}
): Node[Item, Hash] =
  # Walks to leaf `index`, applies `f` there, rebuilds the path bottom-up.
  # Invariant (matches Rust): when we recurse INTO an Empty subtree, `index`
  # is always 0. Holds because the public API picks indices from the holes
  # heap or `t.count`, both of which route to the leftmost-vacant position.
  case n.kind
  of Inner:
    doAssert index < nodeCapacity(n),
      "index " & $index & " out of bounds for height " & $n.height
    let leftCap = nodeCapacity(n.left)
    if index < leftCap:
      newInner(modifyAt(n.left, index, f), n.right)
    else:
      newInner(n.left, modifyAt(n.right, index - leftCap, f))
  of Empty:
    doAssert index == 0,
      "Empty subtree can only be expanded at index 0"
    if n.eHeight == 0:
      f(n)
    else:
      # Always recurse left; right stays lazy Empty. Keeps the right-only-
      # Empty invariant that makes 2^TreeDepth capacity tractable.
      let childEmpty = Node[Item, Hash](kind: Empty, eHeight: n.eHeight - 1)
      newInner(modifyAt(childEmpty, index, f), childEmpty)
  of Leaf:
    doAssert index == 0, "leaf index out of bounds"
    f(n)

func insertAt[Item, Hash](n: Node[Item, Hash]; index: int; item: sink Item): Node[Item, Hash] =
  let item = item
  modifyAt(n, index, proc(leaf: Node[Item, Hash]): Node[Item, Hash] =
    case leaf.kind
    of Leaf:
      doAssert leaf.item.isNone,
        "cannot insert: leaf at this position is already populated"
      Node[Item, Hash](kind: Leaf, item: some(item))
    of Empty:
      Node[Item, Hash](kind: Leaf, item: some(item))
    of Inner:
      doAssert false, "modifyAt handed a non-terminal node to f"
      leaf)

func removeAt[Item, Hash](n: Node[Item, Hash]; index: int): Node[Item, Hash] =
  modifyAt(n, index, proc(leaf: Node[Item, Hash]): Node[Item, Hash] =
    doAssert leaf.kind == Leaf and leaf.item.isSome,
      "cannot remove: leaf is empty"
    Node[Item, Hash](kind: Leaf, item: none(Item)))

func insert*[Item, Hash](t: DynamicMerkleTree[Item, Hash]; item: sink Item):
    tuple[tree: DynamicMerkleTree[Item, Hash], leafIndex: int] =
  ## Returns the new tree and the assigned leaf index (smallest hole if any,
  ## else current ``len``).
  var holes = t.holes
  let leafIndex =
    if holes.len > 0: holes.pop()
    else:             t.count
  doAssert leafIndex < Capacity, "tree at capacity"
  (DynamicMerkleTree[Item, Hash](
     root:  insertAt(t.root, leafIndex, item),
     holes: holes,
     count: t.count + 1),
   leafIndex)

func remove*[Item, Hash](t: DynamicMerkleTree[Item, Hash]; leafIndex: int):
    DynamicMerkleTree[Item, Hash] =
  ## Nulls the leaf and pushes ``leafIndex`` onto the hole heap.
  doAssert leafIndex in 0 ..< Capacity, "leafIndex out of bounds"
  var holes = t.holes
  holes.push(leafIndex)
  DynamicMerkleTree[Item, Hash](
    root:  removeAt(t.root, leafIndex),
    holes: holes,
    count: t.count - 1)

func collectPath[Item, Hash](
    n: Node[Item, Hash]; index: int; depthFromRoot: int; outPath: var MerklePath
): bool =
  # Root→leaf walk; writes siblings into `outPath` in leaf→root order.
  # Returns false if the target leaf is empty or missing.
  case n.kind
  of Empty:
    false
  of Leaf:
    n.item.isSome
  of Inner:
    let
      leftCap = nodeCapacity(n.left)
      slot    = TreeDepth - 1 - depthFromRoot
    if index < leftCap:
      if not collectPath(n.left, index, depthFromRoot + 1, outPath):
        return false
      outPath[slot] = MerkleNode(side: Right, sibling: value(n.right))
    else:
      if not collectPath(n.right, index - leftCap, depthFromRoot + 1, outPath):
        return false
      outPath[slot] = MerkleNode(side: Left, sibling: value(n.left))
    true

func path*[Item, Hash](t: DynamicMerkleTree[Item, Hash]; leafIndex: int): Opt[MerklePath] =
  ## Returns the inclusion proof for ``leafIndex``, or ``Opt.none`` if the
  ## leaf is out of range or unpopulated. Path is leaf → root, 32 entries.
  ## Name matches Rust's ``MerklePath path(index)``.
  if leafIndex notin 0 ..< Capacity:
    return Opt.none(MerklePath)
  var p: MerklePath
  if collectPath(t.root, leafIndex, 0, p):
    Opt.some(p)
  else:
    Opt.none(MerklePath)

func verifyPath*(Hash: typedesc; p: MerklePath; leafDigest: F; root: F): bool =
  ## Walks the path bottom-up using ``Hash.compress``; true iff the
  ## reconstructed root equals ``root``. Call as
  ## ``Poseidon2Hasher.verifyPath(p, leafDigest, root)``.
  mixin compress
  var current = leafDigest
  for node in p:
    current =
      case node.side
      of Left:  Hash.compress(node.sibling, current)
      of Right: Hash.compress(current, node.sibling)
  current == root

func `==`*[Item, Hash](a, b: DynamicMerkleTree[Item, Hash]): bool =
  ## Root-based equality. O(1) on cached roots.
  value(a.root) == value(b.root)

func `$`*[Item, Hash](t: DynamicMerkleTree[Item, Hash]): string =
  ## "(root: 0x..., len: N, capacity: 2^32)"
  "(root: " & value(t.root).toHex() &
    ", len: " & $t.count &
    ", capacity: 2^" & $TreeDepth & ")"

{.pop.}
