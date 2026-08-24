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
  results,
  minilru,
  ../ledger/[balance, types, fee_market, ledger],
  ./crypto/types,
  ./mantle/[operations, tx_hashing, tx_types, gas]

from ./types import Block, MaxBlockSize
from ./mantle/primitives import MaxBlockTxs, SlotNumber

const
  DefaultMempoolCapacity* = 10_240
  MempoolMaxAgeSlots* = 100'u64
  MempoolMinAgeSlots* = 3'u64

func maxMempoolCapacity*(securityParam: uint64 = 1): uint64 {.inline.} =
  ## Returns mempool capacity as 10x the maximum unfinalized branch transactions.
  uint64(10 * max(securityParam, 1'u64) * MaxBlockTxs)

type
  MempoolError* {.pure.} = enum
    TxNotFound

  MempoolItem = object
    tx: SignedMantleTx
    addedAtSlot: SlotNumber

  Mempool* = ref object
    txs*: Table[Hash32, MempoolItem]
    queue*: Deque[Hash32]
    graceCache*: LruCache[Hash32, SignedMantleTx]
    capacity*: uint64
    lastAddedSlot*: SlotNumber

func len*(m: Mempool): int =
  m.txs.len

func init*(_: typedesc[Mempool],
    capacity = uint64(DefaultMempoolCapacity)): Mempool =
  let cap = max(capacity, 1'u64)
  Mempool(
    graceCache: LruCache[Hash32, SignedMantleTx].init(int(cap)),
    capacity: cap
  )

proc remove(m: Mempool, hash: Hash32, moveToGrace: bool) =
  if hash in m.txs:
    try:
      if moveToGrace:
        m.graceCache.put(hash, move(m.txs[hash].tx))
      m.txs.del(hash)
    except KeyError:
      discard

proc compactQueue(m: Mempool) =
  var newQueue = initDeque[Hash32](m.txs.len)
  for h in m.queue:
    if h in m.txs:
      newQueue.addLast(h)
  m.queue = newQueue

proc add*(
    m: Mempool,
    tx: sink SignedMantleTx,
    currentSlot: SlotNumber,
): bool =
  doAssert currentSlot >= m.lastAddedSlot,
    "Mempool transactions must be added in monotonic slot order: currentSlot=" &
    $currentSlot & " < lastAddedSlot=" & $m.lastAddedSlot

  let hash = mantleTxHash(tx.tx)
  if hash in m.txs:
    return false

  while uint64(m.txs.len) >= m.capacity and m.queue.len > 0:
    # Evict oldest transaction to grace cache when capacity is reached
    let oldestHash = m.queue.popFirst()
    if oldestHash in m.txs:
      m.remove(oldestHash, moveToGrace = true)
      break

  if m.queue.len > int(m.capacity * 2) and m.txs.len < m.queue.len div 2:
    m.compactQueue()

  m.txs[hash] = MempoolItem(tx: tx, addedAtSlot: currentSlot)
  m.queue.addLast(hash)
  m.lastAddedSlot = currentSlot
  true

func contains*(m: Mempool, hash: Hash32): bool =
  hash in m.txs

func get*(m: Mempool, hash: Hash32): Result[SignedMantleTx, MempoolError] =
  m.txs.withValue(hash, item):
    return ok(item[].tx)
  let tx = m.graceCache.peek(hash).valueOr:
    return err(MempoolError.TxNotFound)
  ok(tx)

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

proc pruneBlockTxs*(m: Mempool, blk: Block) =
  for stx in blk.txs:
    m.remove(mantleTxHash(stx.tx), moveToGrace = false)

proc selectTxsForProposal*(
    m: Mempool,
    tipLedgerState: LedgerState,
    cfg: LedgerConfig = LedgerConfig(),
    currentSlot: SlotNumber,
    maxTxs: int = MaxBlockTxs,
    maxBytes: int = MaxBlockSize,
): seq[SignedMantleTx] =
  ## Selects transactions for block proposal according to the Execution Market spec:
  ## https://github.com/logos-co/logos-lips/blob/38916aa474164ac4acd81e62d19715e17626be17/docs/blockchain/raw/execution-market.md
  ## Enforces count (maxTxs), execution gas (MAX_EXECUTION_GAS_PER_BLOCK), and body byte size (maxBytes).
  var selected: seq[SignedMantleTx]
  var workingLedger = tipLedgerState.advanceEpochAndMarket(currentSlot, cfg).valueOr:
    tipLedgerState
  var cumulativeExecutionGas = Gas(0)
  var cumulativeBytes = 0

  for hash in m.queue:
    if selected.len >= maxTxs:
      break

    m.txs.withValue(hash, item):
      if currentSlot < item[].addedAtSlot + MempoolMinAgeSlots:
        continue

      let txBytes = encodeSignedMantleTx(item[].tx).len
      if cumulativeBytes + txBytes > maxBytes:
        continue

      let feesRes = workingLedger.mandatory_fees(item[].tx)
      if feesRes.isErr:
        continue

      let (totalCost, execGas, _) = feesRes.get

      let nextExecutionGas = cumulativeExecutionGas.checkedAdd(execGas).valueOr:
        continue
      if nextExecutionGas > MAX_EXECUTION_GAS_PER_BLOCK:
        continue

      let epoch = workingLedger.epochs.activeEpoch.epoch
      var candidate = workingLedger
      let applyRes = candidate.tryApplyTx(item[].tx, epoch, currentSlot)
      if applyRes.isOk and applyRes.get.covers(totalCost):
        selected.add(item[].tx)
        cumulativeExecutionGas = nextExecutionGas
        cumulativeBytes += txBytes
        workingLedger = move(candidate)

  selected

{.pop.}
