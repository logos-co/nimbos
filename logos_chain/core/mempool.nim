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
  std/[deques, tables, times],
  results,
  ../ledger/[balance, types, fee_market, ledger],
  ./crypto/types,
  ./mantle/[operations, primitives, tx_hashing, tx_types, gas],
  ../consensus/clock

from ./types import Block
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

  GraceCache = object
    cache: Table[Hash32, SignedMantleTx]
    queue: Deque[Hash32]
    capacity: uint64

  Mempool* = object
    txs*: OrderedTable[Hash32, MempoolItem]
    graceCache*: GraceCache
    capacity*: uint64
    slotConfig*: SlotConfig

func init(_: typedesc[GraceCache], capacity: uint64 = uint64(
    DefaultMempoolCapacity)): GraceCache =
  GraceCache(capacity: max(capacity, 1'u64))

proc cache(c: var GraceCache, hash: Hash32, tx: SignedMantleTx) =
  if hash in c.cache:
    return
  while uint64(c.queue.len) >= c.capacity:
    c.cache.del(c.queue.popFirst())
  c.cache[hash] = tx
  c.queue.addLast(hash)

func retrieve(c: GraceCache, hash: Hash32): Result[SignedMantleTx, MempoolError] =
  c.cache.withValue(hash, tx):
    return ok(tx)
  err(MempoolError.TxNotFound)

func len*(m: Mempool): int =
  m.txs.len

func init*(_: typedesc[Mempool], slotConfig: SlotConfig,
    capacity: uint64 = uint64(DefaultMempoolCapacity)): Mempool =
  let cap = max(capacity, 1'u64)
  Mempool(
    graceCache: GraceCache.init(capacity = cap),
    capacity: cap,
    slotConfig: slotConfig
  )

proc remove(m: var Mempool, hash: Hash32, moveToGrace: bool = true) =
  if hash in m.txs:
    try:
      let item = m.txs[hash]
      m.txs.del(hash)
      if moveToGrace:
        m.graceCache.cache(hash, item.tx)
    except KeyError:
      discard

proc add*(
    m: var Mempool,
    tx: SignedMantleTx,
): bool =
  let slotNumber = wallclockSlot(uint64(max(getTime().toUnix(), 0'i64)), m.slotConfig)
  let hash = mantleTxHash(tx.tx)
  if hash in m.txs:
    return false

  if uint64(m.len) >= m.capacity:
    # Evict oldest transaction to grace cache when capacity is reached
    var oldestHash: Hash32
    for h in m.txs.keys:
      oldestHash = h
      break
    m.remove(oldestHash, moveToGrace = true)

  m.txs[hash] = MempoolItem(tx: tx, addedAtSlot: slotNumber)
  true

func contains*(m: Mempool, hash: Hash32): bool =
  hash in m.txs

proc get*(m: Mempool, hash: Hash32): Result[SignedMantleTx, MempoolError] =
  if hash in m.txs:
    try:
      return ok(m.txs[hash].tx)
    except KeyError:
      discard
  m.graceCache.retrieve(hash)

proc pruneExpiredTxs*(m: var Mempool) =
  let currentSlot = wallclockSlot(uint64(max(getTime().toUnix(), 0'i64)), m.slotConfig)
  var expiredHashes: seq[Hash32]
  for hash, item in m.txs:
    if currentSlot > item.addedAtSlot + MempoolMaxAgeSlots:
      expiredHashes.add(hash)
    else:
      break

  for hash in expiredHashes:
    m.remove(hash, moveToGrace = true)

proc pruneBlockTxs*(m: var Mempool, blk: Block) =
  for stx in blk.txs:
    m.remove(mantleTxHash(stx.tx), moveToGrace = false)

proc selectTxsForProposal*(
    m: Mempool,
    tipLedgerState: LedgerState,
    maxTxs: int = MaxBlockTxs
): seq[SignedMantleTx] =
  ## Selects transactions for block proposal according to the Execution Market spec:
  ## https://github.com/logos-co/logos-lips/blob/38916aa474164ac4acd81e62d19715e17626be17/docs/blockchain/raw/execution-market.md
  let currentSlot = wallclockSlot(uint64(max(getTime().toUnix(), 0'i64)), m.slotConfig)
  var selected: seq[SignedMantleTx]
  var workingLedger = tipLedgerState
  var cumulativeExecutionGas = Gas(0)

  for item in m.txs.values:
    if selected.len >= maxTxs:
      break

    if currentSlot < item.addedAtSlot + MempoolMinAgeSlots:
      continue

    let feesRes = tipLedgerState.mandatory_fees(item.tx)
    if feesRes.isErr:
      continue

    let (totalCost, execGas, _) = feesRes.get

    let nextExecutionGas = cumulativeExecutionGas.checkedAdd(execGas).valueOr:
      continue
    if nextExecutionGas > MAX_EXECUTION_GAS_PER_BLOCK:
      continue

    let epoch = workingLedger.epochs.activeEpoch.epoch
    let applyRes = workingLedger.tryApplyTx(item.tx, epoch, currentSlot)
    if applyRes.isOk and applyRes.get.balance.covers(totalCost):
      selected.add(item.tx)
      cumulativeExecutionGas = nextExecutionGas
      workingLedger = applyRes.get.state

  selected

{.pop.}
