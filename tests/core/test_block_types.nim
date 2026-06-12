# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import unittest2
import ../../logos_chain/core/mantle/[tx_types, tx_hashing]
import ../../logos_chain/core/types

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
      createSdpActiveOp(SdpActivePayload(
        declarationId: default(DeclarationId),
        nonce: 1'u64,
        metadata: @[],
      )),
    )
    check createBlockRoot([txA, txB]) != createBlockRoot([txB, txA])

  test "createBlockRoot returns zero hash for empty tx list":
    check createBlockRoot([]) == default(Hash32)

  test "createBlockRoot single tx equals that tx hash":
    let tx = sampleTx(
      createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[]),
      )),
    )
    check createBlockRoot([tx]) == mantleTxHash(tx.tx)

  test "createBlockRoot odd leaf count uses zero padding not duplicate last":
    let txA = sampleTx(
      createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[]),
      )),
    )
    let txB = sampleTx(
      createSdpActiveOp(SdpActivePayload(
        declarationId: default(DeclarationId),
        nonce: 2'u64,
        metadata: @[],
      )),
    )
    let txC = sampleTx(
      createSdpWithdrawOp(SdpWithdrawPayload(
        declarationId: default(DeclarationId),
        lockedNoteId: default(NoteId),
        nonce: 3'u64,
      )),
    )
    let hA = mantleTxHash(txA.tx)
    let hB = mantleTxHash(txB.tx)
    let hC = mantleTxHash(txC.tx)
    let zero = default(Hash32)
    check createBlockRoot([txA, txB, txC]) == hashPair(hashPair(hA, hB), hashPair(hC, zero))
    check createBlockRoot([txA, txB, txC]) != createBlockRoot([txA, txB, txC, txC])

  test "blockId is deterministic for same header":
    let tx = sampleTx(
      createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[]),
      )),
    )
    let h = initHeader(
      bedrockVersion = testBedrockVersion,
      parentBlock = default(BlockId),
      slot = 42'u64,
      txs = [tx],
      proofOfLeadership = ProofOfLeadership(
        leaderVoucher: default(RewardVoucher),
        entropyContribution: default(ZkHash),
        proof: DefaultCompressedGroth16Proof,
        leaderKey: default(Ed25519PublicKey),
      ),
    )
    check blockId(h) == blockId(h)

{.pop.}
