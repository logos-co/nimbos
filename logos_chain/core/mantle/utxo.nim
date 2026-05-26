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
  stew/endians2,
  ./primitives, ../../zk/poseidon2/hasher

type Utxo* = object
  opId*: Hash32
  outputIndex*: uint64
  note*: Note

const NoteIdV1DomainTag = "NOTE_ID_V1"

func noteIdV1DomainFr(): FieldElement =
  frFromBytesLE(NoteIdV1DomainTag.toOpenArrayByte(0, NoteIdV1DomainTag.high)).get

func noteIDPreimage(u:Utxo): array[5, FieldElement] =
  ## Preimage for NoteId computation, used in ZK proofs that bind to NoteId.
  ## See `noteId` for the corresponding hash function.
  [
    noteIdV1DomainFr(),
    frFromBytesLEModOrder(u.opId),
    frFromBytesLE(u.outputIndex.toBytesLE).get,
    frFromBytesLE(u.note.value.toBytesLE).get,
    u.note.zkPublicKey,
  ]

func id*(u: Utxo): NoteId =
  ## Poseidon2 commitment over (domain, opId, outputIndex, value, pk).
  ## ``opId`` is a Blake2b digest that may exceed the field modulus, so it
  ## is reduced mod order before being absorbed.
  NoteId(Poseidon2Hasher.digest(noteIDPreimage(u)))

func asField*(id: NoteId): FieldElement = id
  ## `DynamicMerkleTree` Item view: NoteId is already a field element.

{.pop.}
