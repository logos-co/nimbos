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

import constantine/math/[arithmetic, io/io_bigints]
import poseidon2/types

import ../../../logos_chain/core/mantle/[primitives, utxo]
import ./test_helpers

suite "Utxo.id":
  test "deterministic: same Utxo data → same NoteId":
    let
      a = mkUtxo()
      b = mkUtxo()
    check a.id == b.id

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
      reconstructed = NoteId.fromBytes(bytes).get()
    check id == reconstructed

  test "cross-language reference vector matches Rust `test_note_id`":
    # Reference: logos-blockchain/core/src/mantle/ledger.rs:354-370
    # Utxo([0u8;32], 0, Note(100, Fr(456))) → NoteId(Fr("...0367418066"))
    let
      pk = F.fromBig(B.fromDecimal("456"))
      u = Utxo(
        opId: default(Hash32),
        outputIndex: 0,
        note: Note(value: 100, zkPublicKey: pk),
      )
      expected = F.fromBig(B.fromDecimal(
        "7557997998773395727489806263315711564569794358720487479582958381680367418066"
      ))
    check u.id == NoteId(expected)

{.pop.}
