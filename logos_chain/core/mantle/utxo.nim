# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## UTXO record and NoteId derivation.

{.push raises: [], gcsafe.}

import std/options
import stew/endians2

import ./primitives
import poseidon2/[types, io]
import "../../zk/poseidon2/hasher"

type Utxo* = object
  transferHash*: ZkHash
  outputIndex*: int
  note*: Note

const NoteIdV1DomainTag = "NOTE_ID_V1"

func noteIdV1DomainFr(): F =
  frFromBytesLE(NoteIdV1DomainTag.toOpenArrayByte(0, NoteIdV1DomainTag.high)).get

func id*(u: Utxo): NoteId =
  ## Poseidon2 commitment over (domain, transferHash, outputIndex, value, pk).
  let
    transferFr = F.fromBytes(u.transferHash).get
    outputIdxFr = frFromBytesLE(uint64(u.outputIndex).toBytesLE).get
    valueFr = frFromBytesLE(u.note.value.toBytesLE).get
    pkFr = F.fromBytes(u.note.zkPublicKey).get
  NoteId(
    Poseidon2Hasher.digest([noteIdV1DomainFr(), transferFr, outputIdxFr, valueFr, pkFr])
  )

{.pop.}
