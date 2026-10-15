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
  ../../../logos_chain/core/types,
  ../../../logos_chain/core/mantle/
    [primitives, operations, proofs, utxo, poc_verifier],
  ../../../logos_chain/zk/poseidon2/hasher

from libp2p/crypto/rng import newBearSslRng

type TestId* = BlockId

func mkZkPubKey*(seed: byte): ZkPublicKey =
  frFromBytesLE([seed]).get

proc mkRealZkPubKey*(sk: byte): ZkPublicKey =
  ## Circuit-derived PK: `Poseidon2.compress(KDF, sk)`. Use when a test needs
  ## a pk that matches what the zksign prover would emit for a given sk —
  ## e.g. when verifying against committed fixture proofs.
  zkPublicKeyFromSecret(frFromBytesLE([sk]).get)

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

func mkUtxo*(
    value: Value = 100, pkSeed: byte = 1, opIdSeed: byte = 0,
    outputIndex: uint64 = 0,
): Utxo =
  mkUtxoWithPk(mkZkPubKey(pkSeed), value, opIdSeed, outputIndex)

func mkNote*(value: Value, pkSeed: byte): Note =
  Note(value: value, zkPublicKey: mkZkPubKey(pkSeed))

func mkId*(seed: byte): TestId =
  var id: TestId
  id[0] = seed
  id

func mkTxHash*(seed: byte = 0x42): ZkHash =
  mkId(seed)

func mkSignedTransferTx*(
    inputs: openArray[NoteId],
    outputs: openArray[Note],
    opProofs: seq[OpProof] = @[OpProof(kind: opfTransfer, transferProof: default(ZkSigProof))],
): SignedMantleTx =
  let op = createTransferOp(
    TransferPayload(inputs: Inputs(noteIds: @inputs), outputs: Outputs(notes: @outputs))
  )
  SignedMantleTx(
    tx: MantleTx(ops: @[op]),
    opProofs: opProofs,
  )

func createHashedSignedMantleTx*(
    signedTx: sink SignedMantleTx,
): Result[HashedSignedMantleTx, EncodingError] {.inline.} =
  let h = ?mantleTxHash(signedTx.tx)
  ok(createHashedSignedMantleTxForTest(signedTx, h))

func mkHashedSignedTx*(stx: sink SignedMantleTx): HashedSignedMantleTx =
  let h = mantleTxHash(stx.tx).expect("valid tx for mkHashedSignedTx")
  createHashedSignedMantleTxForTest(stx, h)

func mkHashedSignedTx*(stx: sink SignedMantleTx, hash: Hash32): HashedSignedMantleTx =
  createHashedSignedMantleTxForTest(stx, hash)

func mkTransferTx*(
    inputs: openArray[NoteId],
    outputs: openArray[Note],
    opProofs: seq[OpProof] = @[OpProof(kind: opfTransfer, transferProof: default(ZkSigProof))],
): HashedSignedMantleTx =
  mkHashedSignedTx(mkSignedTransferTx(inputs, outputs, opProofs))

func mkHashedTx*(
    ops: seq[Op],
    opProofs: seq[OpProof],
): HashedSignedMantleTx =
  mkHashedSignedTx(SignedMantleTx(tx: MantleTx(ops: ops), opProofs: opProofs))

func mkValidTransferTx*(
    inputs: openArray[NoteId], outputs: openArray[Note]
): ValidSignedMantleTx =
  createValidTxForTest(mkTransferTx(inputs, outputs))

func mkProof*(): ProofOfLeadership =
  default(ProofOfLeadership)

func unhashed*(tx: sink SignedMantleTx): HashedSignedMantleTx =
  ## Wraps `tx` in a HashedSignedMantleTx with default(Hash32).
  ## Only for tests where the code under test does not read `htx.hash` (e.g. stage-1 genesis validation,
  ## non-cryptographic stateless validation).
  createHashedSignedMantleTxForTest(tx, default(Hash32))

func unhashedTx*(ops: openArray[Op]): HashedSignedMantleTx =
  ## Creates an unhashed HashedSignedMantleTx with default proofs for multiple ops.
  var proofs = newSeqOfCap[OpProof](ops.len)
  for op in ops:
    proofs.add defaultOpProofForOpcode(op.opcode).expect("supported opcode")
  createHashedSignedMantleTxForTest(
    SignedMantleTx(tx: MantleTx(ops: @ops), opProofs: proofs),
    default(Hash32),
  )

func unhashedTx*(op: Op): HashedSignedMantleTx =
  ## Creates an unhashed HashedSignedMantleTx with default proof for a single op.
  ## For tests that only validate stateless logic where hash is not verified.
  unhashedTx([op])

func mkValidTx*(htx: HashedSignedMantleTx): ValidSignedMantleTx =
  createValidTxForTest(htx)

func mkValidTx*(stx: sink SignedMantleTx): ValidSignedMantleTx =
  mkValidTx(mkHashedSignedTx(stx))

func mkValidGenesisTx*(htx: HashedSignedMantleTx): ValidGenesisMantleTx =
  createValidGenesisTxForTest(htx)


proc mkEdKeyPair*(rng: ref HmacDrbgContext): EdKeyPair =
  ## Random Ed25519 keypair. Caller provides the rng so all keypairs minted
  ## within a single test share one source and remain reproducible-by-order.
  EdKeyPair.random(newBearSslRng(rng))

func mkChannelId*(seed: byte): ChannelId =
  var c: ChannelId
  c[0] = seed
  c

{.pop.}
