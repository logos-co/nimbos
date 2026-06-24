# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  bearssl/rand,
  libp2p/crypto/ed25519/ed25519,
  ../../../logos_chain/core/[types, crypto/hashing],
  ../../../logos_chain/core/mantle/
    [primitives, operations, proofs, tx_types, utxo],
  ../../../logos_chain/zk/poseidon2/hasher

type TestId* = BlockId

func mkZkPubKey(seed: byte): ZkPublicKey =
  frFromBytesLE([seed]).get

proc mkRealZkPubKey*(sk: byte): ZkPublicKey =
  ## Circuit-derived PK: `Poseidon2.compress(KDF, sk)`. Use when a test needs
  ## a pk that matches what the zksign prover would emit for a given sk —
  ## e.g. when verifying against committed fixture proofs.
  zkPublicKeyFromSecret(frFromBytesLE([sk]).get)

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

func mkUtxoWithPk*(
    pk: ZkPublicKey, value: Value = 100, opIdSeed: byte = 0,
    outputIndex: uint64 = 0,
): Utxo =
  ## Sibling of `mkUtxo` that takes a raw pk instead of deriving one from a
  ## seed. Used by fixture-driven tests that need a specific zkPublicKey.
  var opId: Hash32
  opId[0] = opIdSeed
  Utxo(
    opId: opId,
    outputIndex: outputIndex,
    note: Note(value: value, zkPublicKey: pk),
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
    tx: MantleTx(ops: @[op]),
    opProofs: @[OpProof(kind: opfTransfer, transferProof: default(ZkSigProof))],
  )

func mkProof*(): ProofOfLeadership =
  default(ProofOfLeadership)

proc mkEdKeyPair*(rng: ref HmacDrbgContext): EdKeyPair =
  ## Random Ed25519 keypair. Caller provides the rng so all keypairs minted
  ## within a single test share one source and remain reproducible-by-order.
  EdKeyPair.random(rng[])

func mkChannelId*(seed: byte): ChannelId =
  var c: ChannelId
  c[0] = seed
  c

{.pop.}
