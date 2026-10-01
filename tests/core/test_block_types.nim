# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  ../../logos_chain/core/mantle/[tx_types, tx_hashing],
  ../../logos_chain/core/types

suite "core/types":
  const testBedrockVersion = 1'u8

  proc sampleTx(op: Op): SignedMantleTx =
    SignedMantleTx(tx: MantleTx(ops: @[op]), opProofs: @[])

  test "initBlock accepts empty tx list":
    let
      tx = MantleTx(ops: @[])
      h = initHeader(
        bedrockVersion = testBedrockVersion,
        parentBlock = default(BlockId),
        slot = 0'u64,
        uncleHeaders = [],
        txs = [SignedMantleTx(tx: tx, opProofs: @[])],
        proofOfLeadership = ProofOfLeadership(
          leaderVoucher: default(RewardVoucher),
          entropyContribution: default(ZkHash),
          proof: DefaultCompressedGroth16Proof,
          leaderKey: default(Ed25519PublicKey),
        ),
      ).get
      b = initBlock(h, uncleHeaders = [], txs = [])
    check b.txs.len == 0
    check b.header.slot == 0'u64

  test "blockId returns 32-byte hash":
    let
      tx = MantleTx(ops: @[])
      h = initHeader(
        bedrockVersion = testBedrockVersion,
        parentBlock = default(BlockId),
        slot = 0'u64,
        uncleHeaders = [],
        txs = [SignedMantleTx(tx: tx, opProofs: @[])],
        proofOfLeadership = ProofOfLeadership(
          leaderVoucher: default(RewardVoucher),
          entropyContribution: default(ZkHash),
          proof: DefaultCompressedGroth16Proof,
          leaderKey: default(Ed25519PublicKey),
        ),
      ).get
      id = blockId(h)
    check id.len == 32

  test "merkle_root changes when tx order changes":
    let
      txA = sampleTx(
        createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[]),
        )),
      )
      txB = sampleTx(
        createSdpActiveOp(ActiveMessage(
          declarationId: default(DeclarationId),
          nonce: 1'u64,
          metadata: @[],
        )),
      )
      hA = mantleTxHash(txA.tx).get
      hB = mantleTxHash(txB.tx).get
    check merkle_root([hA, hB]) != merkle_root([hB, hA])

  test "merkle_root returns zero hash for empty tx list":
    check merkle_root(openArray[Hash32]([])) == default(Hash32)

  test "merkle_root single tx equals that tx hash":
    let
      tx = sampleTx(
        createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[]),
        )),
      )
      h = mantleTxHash(tx.tx).get
    check merkle_root([h]) == h

  test "merkle_root odd leaf count uses zero padding not duplicate last":
    let
      txA = sampleTx(
        createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[]),
        )),
      )
      txB = sampleTx(
        createSdpActiveOp(ActiveMessage(
          declarationId: default(DeclarationId),
          nonce: 2'u64,
          metadata: @[],
        )),
      )
      txC = sampleTx(
        createSdpWithdrawOp(WithdrawMessage(
          declarationId: default(DeclarationId),
          lockedNoteId: default(NoteId),
          nonce: 3'u64,
        )),
      )
      hA = mantleTxHash(txA.tx).get
      hB = mantleTxHash(txB.tx).get
      hC = mantleTxHash(txC.tx).get
      zero = default(Hash32)
    check merkle_root([hA, hB, hC]) == hashPair(hashPair(hA, hB), hashPair(hC, zero))
    check merkle_root([hA, hB, hC]) != merkle_root([hA, hB, hC, hC])

  test "blockId is deterministic for same header":
    let
      tx = sampleTx(
        createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[]),
        )),
      )
      h = initHeader(
        bedrockVersion = 1'u8,
        parentBlock = default(BlockId),
        slot = SlotNumber(100),
        uncleHeaders = [],
        txs = [tx],
        proofOfLeadership = ProofOfLeadership(
          leaderVoucher: default(RewardVoucher),
          entropyContribution: default(ZkHash),
          proof: DefaultCompressedGroth16Proof,
          leaderKey: default(Ed25519PublicKey),
        ),
      ).get
    check blockId(h) == blockId(h)

  test "merkle_root directly accepts list of hashes":
    let
      txA = sampleTx(createTransferOp(TransferPayload(inputs: Inputs(noteIds: @[]), outputs: Outputs(notes: @[]))))
      txB = sampleTx(createSdpActiveOp(ActiveMessage(declarationId: default(DeclarationId), nonce: 1'u64, metadata: @[])))
      hA = mantleTxHash(txA.tx).get
      hB = mantleTxHash(txB.tx).get
      hashes = [hA, hB]
    check merkle_root(hashes) == hashPair(hA, hB)
    check merkle_root([txA, txB]).get == merkle_root(hashes)
    check merkle_root(openArray[Hash32]([])) == default(Hash32)
    check merkle_root([hA]) == hA

    # Malformed tx (e.g. inputs exceeding uint8 limit) returns EncodingError
    let malformedTx = sampleTx(createTransferOp(TransferPayload(
      inputs: Inputs(noteIds: newSeq[NoteId](256)),
      outputs: Outputs(notes: @[]),
    )))
    check merkle_root([malformedTx]).error == EncodingError.InputsCountExceeded

  test "initHeader accepts openArray[Hash32]":
    let
      tx = sampleTx(createTransferOp(TransferPayload(inputs: Inputs(noteIds: @[]), outputs: Outputs(notes: @[]))))
      hx = mantleTxHash(tx.tx).get
      pol = ProofOfLeadership(
        leaderVoucher: default(RewardVoucher),
        entropyContribution: default(ZkHash),
        proof: DefaultCompressedGroth16Proof,
        leaderKey: default(Ed25519PublicKey),
      )
      hFromHashes = initHeader(1'u8, default(BlockId), SlotNumber(10), [], [hx], pol)
      hFromTxs = initHeader(1'u8, default(BlockId), SlotNumber(10), [], [tx], pol).get
    check hFromHashes == hFromTxs

  test "initHeader returns error for malformed tx":
    var invalidInputs: seq[NoteId]
    for i in 0 .. 255:
      invalidInputs.add(default(NoteId))
    let
      malformedTx = sampleTx(createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: invalidInputs), outputs: Outputs(notes: @[])
      )))
      pol = ProofOfLeadership(
        leaderVoucher: default(RewardVoucher),
        entropyContribution: default(ZkHash),
        proof: DefaultCompressedGroth16Proof,
        leaderKey: default(Ed25519PublicKey),
      )
    check initHeader(1'u8, default(BlockId), SlotNumber(10), [], [malformedTx], pol).error == EncodingError.InputsCountExceeded

  test "initProposal accepts References directly":
    var refs: References
    let
      tx = sampleTx(createTransferOp(TransferPayload(inputs: Inputs(noteIds: @[]), outputs: Outputs(notes: @[]))))
      hx = mantleTxHash(tx.tx).get
    refs[0] = hx

    let
      pol = ProofOfLeadership(
        leaderVoucher: default(RewardVoucher),
        entropyContribution: default(ZkHash),
        proof: DefaultCompressedGroth16Proof,
        leaderKey: default(Ed25519PublicKey),
      )
      h = initHeader(1'u8, default(BlockId), SlotNumber(10), [], [hx], pol)
      prop = initProposal(h, [], refs, DefaultEd25519Signature)
    check prop.references[0] == hx

{.pop.}
