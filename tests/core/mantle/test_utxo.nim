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

import ../../../logos_chain/core/mantle/[primitives, utxo]

func mkUtxo(value: Value = 100; outputIndex = 0; pkSeed: byte = 1): Utxo =
  var
    transferHash: ZkHash       # all zeros
    pk: ZkPublicKey            # all zeros except first byte for variety
  pk[0] = pkSeed
  Utxo(
    transferHash: transferHash,
    outputIndex: outputIndex,
    note: Note(value: value, zkPublicKey: pk))

suite "Utxo.id":
  test "deterministic: same Utxo → same NoteId":
    let u = mkUtxo()
    check u.id == u.id

  test "different value → different NoteId":
    let
      a = mkUtxo(value = 100)
      b = mkUtxo(value = 101)
    check a.id != b.id

  test "different outputIndex → different NoteId":
    let
      a = mkUtxo(outputIndex = 0)
      b = mkUtxo(outputIndex = 1)
    check a.id != b.id

  test "different pk → different NoteId":
    let
      a = mkUtxo(pkSeed = 1)
      b = mkUtxo(pkSeed = 2)
    check a.id != b.id

  test "round-trip: id.toBytes ↔ NoteId.fromBytes":
    let
      id = mkUtxo().id
      bytes = id.toBytes
      reconstructed = NoteId.fromBytes(bytes).get
    check id == reconstructed

{.pop.}
