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
    let tx = MantleTx(ops: @[])
    let h = initHeader(
      bedrockVersion = testBedrockVersion,
      parentBlock = default(BlockId),
      slot = 0'u64,
      txs = [SignedMantleTx(tx: tx, opProofs: @[])],
      proofOfLeadership = ProofOfLeadership(
        leaderVoucher: default(RewardVoucher),
        entropyContribution: default(ZkHash),
        proof: DefaultCompressedGroth16Proof,
        leaderKey: default(Ed25519PublicKey),
      ),
    )
    let b = initBlock(h, txs = [])
    check b.txs.len == 0
    check b.header.slot == 0'u64

  test "blockId returns 32-byte hash":
    let tx = MantleTx(ops: @[])
    let h = initHeader(
      bedrockVersion = testBedrockVersion,
      parentBlock = default(BlockId),
      slot = 0'u64,
      txs = [SignedMantleTx(tx: tx, opProofs: @[])],
      proofOfLeadership = ProofOfLeadership(
        leaderVoucher: default(RewardVoucher),
        entropyContribution: default(ZkHash),
        proof: DefaultCompressedGroth16Proof,
        leaderKey: default(Ed25519PublicKey),
      ),
    )
    let id = blockId(h)
    check id.len == 32

  test "createBlockRoot changes when tx order changes":
    let txA = sampleTx(
      createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[]),
      )),
    )
    let txB = sampleTx(
      createSdpActiveOp(ActiveMessage(
        declarationId: default(DeclarationId),
        nonce: 1'u64,
        metadata: @[],
      )),
    )
    let hA = mantleTxHash(txA.tx)
    let hB = mantleTxHash(txB.tx)
    check createBlockRoot([hA, hB]) != createBlockRoot([hB, hA])

  test "createBlockRoot returns zero hash for empty tx list":
    check createBlockRoot(openArray[Hash32]([])) == default(Hash32)

  test "createBlockRoot single tx equals that tx hash":
    let tx = sampleTx(
      createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[]),
      )),
    )
    let h = mantleTxHash(tx.tx)
    check createBlockRoot([h]) == h

  test "createBlockRoot odd leaf count uses zero padding not duplicate last":
    let txA = sampleTx(
      createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[]),
      )),
    )
    let txB = sampleTx(
      createSdpActiveOp(ActiveMessage(
        declarationId: default(DeclarationId),
        nonce: 2'u64,
        metadata: @[],
      )),
    )
    let txC = sampleTx(
      createSdpWithdrawOp(WithdrawMessage(
        declarationId: default(DeclarationId),
        lockedNoteId: default(NoteId),
        nonce: 3'u64,
      )),
    )
    let hA = mantleTxHash(txA.tx)
    let hB = mantleTxHash(txB.tx)
    let hC = mantleTxHash(txC.tx)
    let zero = default(Hash32)
    check createBlockRoot([hA, hB, hC]) == hashPair(hashPair(hA, hB), hashPair(hC, zero))
    check createBlockRoot([hA, hB, hC]) != createBlockRoot([hA, hB, hC, hC])

  test "blockId is deterministic for same header":
    let tx = sampleTx(
      createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[]),
      )),
    )
    let h = initHeader(
      bedrockVersion = 1'u8,
      parentBlock = default(BlockId),
      slot = SlotNumber(100),
      txs = [tx],
      proofOfLeadership = ProofOfLeadership(
        leaderVoucher: default(RewardVoucher),
        entropyContribution: default(ZkHash),
        proof: DefaultCompressedGroth16Proof,
        leaderKey: default(Ed25519PublicKey),
      ),
    )
    check blockId(h) == blockId(h)

  test "createBlockRoot directly accepts list of hashes":
    let txA = sampleTx(createTransferOp(TransferPayload(inputs: Inputs(noteIds: @[]), outputs: Outputs(notes: @[]))))
    let txB = sampleTx(createSdpActiveOp(ActiveMessage(declarationId: default(DeclarationId), nonce: 1'u64, metadata: @[])))
    let hA = mantleTxHash(txA.tx)
    let hB = mantleTxHash(txB.tx)

    let hashes = [hA, hB]
    check createBlockRoot(hashes) == hashPair(hA, hB)
    check createBlockRoot([txA, txB]) == createBlockRoot(hashes)
    check createBlockRoot(openArray[Hash32]([])) == default(Hash32)
    check createBlockRoot([hA]) == hA

  test "initHeader accepts openArray[Hash32]":
    let tx = sampleTx(createTransferOp(TransferPayload(inputs: Inputs(noteIds: @[]), outputs: Outputs(notes: @[]))))
    let hx = mantleTxHash(tx.tx)
    let pol = ProofOfLeadership(
      leaderVoucher: default(RewardVoucher),
      entropyContribution: default(ZkHash),
      proof: DefaultCompressedGroth16Proof,
      leaderKey: default(Ed25519PublicKey),
    )
    let hFromHashes = initHeader(1'u8, default(BlockId), SlotNumber(10), [hx], pol)
    let hFromTxs = initHeader(1'u8, default(BlockId), SlotNumber(10), [tx], pol)
    check hFromHashes == hFromTxs

  test "initProposal accepts References directly":
    var refs: References
    let tx = sampleTx(createTransferOp(TransferPayload(inputs: Inputs(noteIds: @[]), outputs: Outputs(notes: @[]))))
    let hx = mantleTxHash(tx.tx)
    refs[0] = hx

    let pol = ProofOfLeadership(
      leaderVoucher: default(RewardVoucher),
      entropyContribution: default(ZkHash),
      proof: DefaultCompressedGroth16Proof,
      leaderKey: default(Ed25519PublicKey),
    )
    let h = initHeader(1'u8, default(BlockId), SlotNumber(10), [hx], pol)
    let prop = initProposal(h, refs, DefaultEd25519Signature)
    check prop.references[0] == hx

{.pop.}
