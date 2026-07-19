# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## In-memory mempool for storing verified SignedMantleTx.

{.push raises: [], gcsafe.}

import
  std/tables,
  results,
  ./types

type
  Mempool* = object
    txs: Table[Hash32, SignedMantleTx]

func init*(_: typedesc[Mempool]): Mempool =
  Mempool()

proc add*(m: var Mempool, tx: SignedMantleTx): bool =
  let hash = mantleTxHash(tx.tx)
  if hash in m.txs:
    return false
  m.txs[hash] = tx
  true

func contains*(m: Mempool, hash: Hash32): bool =
  hash in m.txs

func get*(m: Mempool, hash: Hash32): Opt[SignedMantleTx] =
  if hash in m.txs:
    ok(m.txs.getOrDefault(hash))
  else:
    err()

proc remove*(m: var Mempool, hash: Hash32): bool =
  if hash in m.txs:
    m.txs.del(hash)
    true
  else:
    false

func len*(m: Mempool): int =
  m.txs.len
