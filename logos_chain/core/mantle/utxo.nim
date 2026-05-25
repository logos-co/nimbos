# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## UTXO record and NoteId derivation.

{.push raises: [], gcsafe.}

import
  std/options,
  stew/endians2, poseidon2/types,
  ./primitives, "../../zk/poseidon2/hasher"

type Utxo* = object
  opId*: Hash32
  outputIndex*: int
  note*: Note

const NoteIdV1DomainTag = "NOTE_ID_V1"

func noteIdV1DomainFr(): F =
  frFromBytesLE(NoteIdV1DomainTag.toOpenArrayByte(0, NoteIdV1DomainTag.high)).get

func id*(u: Utxo): NoteId =
  ## Poseidon2 commitment over (domain, opId, outputIndex, value, pk).
  ## ``opId`` is a Blake2b digest that may exceed the field modulus, so it
  ## is reduced mod order before being absorbed.
  let
    opIdFr = frFromBytesLEModOrder(u.opId)
    outputIdxFr = frFromBytesLE(uint64(u.outputIndex).toBytesLE).get
    valueFr = frFromBytesLE(u.note.value.toBytesLE).get
    pkFr = u.note.zkPublicKey
  NoteId(
    Poseidon2Hasher.digest([noteIdV1DomainFr(), opIdFr, outputIdxFr, valueFr, pkFr])
  )

func asField*(id: NoteId): F = id
  ## `DynamicMerkleTree` Item view: NoteId is already a field element.

{.pop.}
