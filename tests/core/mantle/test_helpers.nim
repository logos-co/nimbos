# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import std/options

import
  "../../../logos_chain/core/block/types",
  ../../../logos_chain/core/crypto/hashing,
  ../../../logos_chain/core/mantle/
    [primitives, operations, proofs, tx_types, utxo]

type TestId* = BlockId

func mkZkPubKey(seed: byte): ZkPublicKey =
  var bytes: array[32, byte]
  bytes[0] = seed
  F.fromBytes(bytes).get

func mkUtxo*(
    value: Value = 100, pkSeed: byte = 1, opIdSeed: byte = 0,
    outputIndex: uint64 = 0,
): Utxo =
  var opId: Hash32
  opId[0] = opIdSeed
  Utxo(
    opId: opId,
    outputIndex: outputIndex,
    note: Note(value: value, zkPublicKey: mkZkPubKey(pkSeed)),
  )

func mkNote*(value: Value, pkSeed: byte): Note =
  Note(value: value, zkPublicKey: mkZkPubKey(pkSeed))

func mkTxHash*(seed: byte = 0x42): ZkHash =
  var h: ZkHash
  h[0] = seed
  h

func mkId*(seed: byte): TestId =
  var id: TestId
  id[0] = seed
  id

func mkTransferTx*(
    inputs: openArray[NoteId], outputs: openArray[Note]
): SignedMantleTx =
  let op = createTransferOp(
    TransferPayload(inputs: Inputs(noteIds: @inputs), outputs: Outputs(notes: @outputs))
  )
  SignedMantleTx(
    tx: MantleTx(ops: @[op], permanentStorageGasPrice: 0, executionGasPrice: 0),
    opProofs: @[OpProof(kind: opfTransfer, transferProof: default(ZkSigProof))],
  )

func mkProof*(): ProofOfLeadership =
  default(ProofOfLeadership)

{.pop.}
