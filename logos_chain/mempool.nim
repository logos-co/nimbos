# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## In-memory mempool for storing verified SignedMantleTx.

{.push raises: [], gcsafe.}

import
  std/[deques, tables],
  results,
  ./core/types

from ./core/mantle/primitives import MaxBlockTxs

type
  MempoolError* = enum
    TxNotFound

  Mempool* = object
    txs: Table[Hash32, SignedMantleTx]
    queue: Deque[Hash32]

func init*(_: typedesc[Mempool]): Mempool =
  Mempool()

proc add*(m: var Mempool, tx: SignedMantleTx): bool =
  let hash = mantleTxHash(tx.tx)
  if hash in m.txs:
    return false
  m.txs[hash] = tx
  m.queue.addLast(hash)
  true

func contains*(m: Mempool, hash: Hash32): bool =
  hash in m.txs

func get*(m: Mempool, hash: Hash32): Result[SignedMantleTx, MempoolError] =
  m.txs.withValue(hash, val):
    return ok(val)
  err(TxNotFound)

proc pruneQueue*(m: var Mempool) =
  ## Compacts the queue by dropping dead hashes of removed transactions.
  var newQueue = initDeque[Hash32]()
  for hash in m.queue:
    if hash in m.txs:
      newQueue.addLast(hash)
  m.queue = newQueue

proc remove*(m: var Mempool, hash: Hash32): bool =
  if hash in m.txs:
    m.txs.del(hash)
    # Prune queue when dead hashes exceed active items to bound memory growth
    # while avoiding frequent O(N) queue compaction on every single remove.
    if m.queue.len > 2 * m.txs.len + 100:
      m.pruneQueue()
    true
  else:
    false

func selectTxsForProposal*(
    m: Mempool,
): seq[SignedMantleTx] =
  ## Selects up to MaxBlockTxs transactions in FIFO order.
  ## Read-only zero-allocation traversal using withValue.
  var selected: seq[SignedMantleTx]
  for hash in m.queue:
    if selected.len >= MaxBlockTxs:
      break
    m.txs.withValue(hash, val):
      selected.add(val)
  selected

func len*(m: Mempool): int =
  m.txs.len
