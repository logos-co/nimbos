# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## In-memory transaction pool for Mantle transactions.
## Transactions are stored in insertion order and dynamically evaluated against
## active LedgerState base fee rates during block proposal construction.
## Spec: [Execution Market — Block Construction](https://github.com/logos-co/logos-lips/blob/38916aa474164ac4acd81e62d19715e17626be17/docs/blockchain/raw/execution-market.md#block-builder-mechanism-block-construction)

{.push raises: [], gcsafe.}

import
  std/[deques, tables],
  minilru,
  results,
  ./core/crypto/types,
  ./core/mantle/[gas, proofs, tx_hashing, tx_types]

from ./core/mantle/primitives import MaxBlockTxs, SlotNumber
from ./core/types import ValidBlock

const
  DefaultMempoolCapacity* = 10_240
  MempoolMaxAgeSlots* = 100'u64

func maxMempoolCapacity*(securityParam: uint64 = 1): uint64 {.inline.} =
  ## Returns mempool capacity as 10x the maximum unfinalized branch transactions.
  uint64(10 * max(securityParam, 1'u64) * MaxBlockTxs)

type
  MempoolError* {.pure.} = enum
    TxNotFound

  MempoolItem* = ref object
    tx*: ValidSignedMantleTx
    addedAtSlot*: SlotNumber
    byteSize*: Opt[int] ## Lazily computed serialized byte length; cached on first proposal evaluation to avoid re-encoding
    execGas*: Opt[Gas]  ## Lazily computed execution gas; cached on first proposal evaluation to avoid repeated gas checks

  Mempool* = ref object
    txs*: Table[Hash32, MempoolItem]
    queue*: Deque[Hash32]
    graceCache*: LruCache[Hash32, MempoolItem]
    capacity*: uint64
    lastAddedSlot*: SlotNumber

func len*(m: Mempool): int =
  m.txs.len

func init*(_: typedesc[Mempool],
    capacity = uint64(DefaultMempoolCapacity)): Mempool =
  let cap = max(capacity, 1'u64)
  Mempool(
    graceCache: LruCache[Hash32, MempoolItem].init(int(cap)),
    capacity: cap
  )

proc remove*(m: Mempool, hash: Hash32, moveToGrace: bool = false) =
  m.txs.withValue(hash, item):
    if moveToGrace:
      m.graceCache.put(hash, item[])
    m.txs.del(hash)

proc compactQueue(m: Mempool) =
  var newQueue = initDeque[Hash32](m.txs.len)
  for h in m.queue:
    if h in m.txs:
      newQueue.addLast(h)
  m.queue = newQueue

proc add*(
    m: Mempool,
    tx: sink ValidSignedMantleTx,
    currentSlot: SlotNumber,
): bool =
  # Clamp to lastAddedSlot to preserve monotonic insertion order against minor clock skew/NTP slewing
  let effectiveSlot = max(currentSlot, m.lastAddedSlot)

  let hash = tx.hash

  if hash in m.txs:
    return false

  # If transaction is currently in grace cache, remove it from grace and promote to active txs
  m.graceCache.del(hash)

  while uint64(m.txs.len) >= m.capacity and m.queue.len > 0:
    # Evict oldest transaction to grace cache when capacity is reached
    let oldestHash = m.queue.popFirst()
    if oldestHash in m.txs:
      m.remove(oldestHash, moveToGrace = true)
      break

  if m.queue.len > int(m.capacity * 2) and m.txs.len < m.queue.len div 2:
    m.compactQueue()

  m.txs[hash] = MempoolItem(
    tx: tx,
    addedAtSlot: effectiveSlot,
    byteSize: Opt.none(int),
    execGas: Opt.none(Gas),
  )
  m.queue.addLast(hash)
  m.lastAddedSlot = effectiveSlot
  true

func contains*(m: Mempool, hash: Hash32): bool =
  ## Returns true if the transaction is in the active mempool or grace cache.
  ## Any transaction present here has already passed stateless validation.
  hash in m.txs or m.graceCache.peek(hash).isSome

func get*(m: Mempool, hash: Hash32): Result[ValidSignedMantleTx, MempoolError] =
  m.txs.withValue(hash, item):
    return ok(item[].tx)
  let item = m.graceCache.peek(hash).valueOr:
    return err(MempoolError.TxNotFound)
  ok(item.tx)

proc pruneExpiredTxs*(m: Mempool, currentSlot: SlotNumber) =
  while m.queue.len > 0:
    let hash = m.queue.peekFirst()
    var isExpired = false
    var found = false
    m.txs.withValue(hash, item):
      found = true
      if currentSlot > item[].addedAtSlot + MempoolMaxAgeSlots:
        isExpired = true

    if not found:
      discard m.queue.popFirst()
    elif isExpired:
      discard m.queue.popFirst()
      m.remove(hash, moveToGrace = true)
    else:
      break

proc pruneBlockTxs*(m: Mempool, blk: ValidBlock) =
  # TODO(mempool): Retain mined transactions in graceCache so concurrent or competing
  # fork proposals can resolve shared references during block reconstruction.
  # In a follow-up PR, replace this with an unfinalized canonical transaction index
  # (tip to LIB) to eliminate reliance on bounded LRU grace eviction under high mempool churn.
  for vtx in blk.txs:
    m.remove(vtx.hash, moveToGrace = true)

func isKnownValid*(m: Mempool, tx: SignedMantleTx, txHash: Hash32): bool =
  ## Light validation check: checks if transaction is present in the mempool
  ## with identical cryptographic proofs using precomputed txHash.
  ## Pre-checks (cheapest to most expensive):
  ## 1. Mempool existence & non-emptiness (< 1 ns)
  ## 2. Structural 1:1 proof count alignment (< 2 ns)
  ## 3. Opcode-to-proof kind matching (< 5 ns)
  ## Lookup & verification:
  ## 4. Mempool lookup using precomputed txHash (~10 ns)
  ## 5. Proof equivalence memory comparison (~10-20 ns, requires poolTx from lookup)
  if m == nil or m.len == 0:
    return false

  if tx.tx.ops.len != tx.opProofs.len:
    return false

  for i in 0 ..< tx.tx.ops.len:
    if tx.opProofs[i].kind != expectedOpProofKindForOpcode(tx.tx.ops[i].opcode):
      return false

  let poolTx = m.get(txHash).valueOr:
    return false

  sameOpProofs(poolTx.opProofs, tx.opProofs)

func classifyBlockTxs*(
    m: Mempool,
    txs: openArray[SignedMantleTx],
): tuple[vtxs: seq[ValidSignedMantleTx], unverifiedIndices: seq[int]] =
  ## Classifies transactions against the mempool into an ordered sequence of
  ## ValidSignedMantleTx with precomputed hashes and records the indices of
  ## unverified transactions needing stateless validation.
  var vtxs = newSeqOfCap[ValidSignedMantleTx](txs.len)
  var unverifiedIndices: seq[int]
  if m == nil or m.len == 0:
    for i in 0 ..< txs.len:
      vtxs.add(ValidSignedMantleTx(signedTx: txs[i], hash: mantleTxHash(txs[i].tx)))
      unverifiedIndices.add(i)
    return (vtxs, unverifiedIndices)
  for i in 0 ..< txs.len:
    let h = mantleTxHash(txs[i].tx)
    vtxs.add(ValidSignedMantleTx(signedTx: txs[i], hash: h))
    if not m.isKnownValid(txs[i], h):
      unverifiedIndices.add(i)
  (vtxs, unverifiedIndices)

{.pop.}
