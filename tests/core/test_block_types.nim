# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  ../testutil,
  ./mantle/test_helpers,
  ../../logos_chain/core/types

suite "core/types":
  const testBedrockVersion = 1'u8


  test "initBlock accepts empty tx list":
    let
      h = initHeader(
        bedrockVersion = testBedrockVersion,
        parentBlock = default(BlockId),
        slot = 0'u64,
        uncleHeaders = [],
        txHashes = openArray[Hash32]([]),
        proofOfLeadership = ProofOfLeadership(
          leaderVoucher: default(RewardVoucher),
          entropyContribution: default(ZkHash),
          proof: DefaultCompressedGroth16Proof,
          leaderKey: default(Ed25519PublicKey),
        ),
      )
      b = initBlock(h, uncleHeaders = [], txs = [])
    check b.txs.len == 0
    check b.header.slot == 0'u64

  test "blockId returns 32-byte hash":
    let
      hx = mkTxHash(1)
      h = initHeader(
        bedrockVersion = testBedrockVersion,
        parentBlock = default(BlockId),
        slot = 0'u64,
        uncleHeaders = [],
        txHashes = [hx],
        proofOfLeadership = ProofOfLeadership(
          leaderVoucher: default(RewardVoucher),
          entropyContribution: default(ZkHash),
          proof: DefaultCompressedGroth16Proof,
          leaderKey: default(Ed25519PublicKey),
        ),
      )
      id = blockId(h)
    check id.len == 32

  test "merkle_root changes when tx order changes":
    let
      hA = mkTxHash(1)
      hB = mkTxHash(2)
    check merkle_root([hA, hB]) != merkle_root([hB, hA])

  test "merkle_root returns zero hash for empty tx list":
    check merkle_root(openArray[Hash32]([])) == default(Hash32)

  test "merkle_root single tx equals that tx hash":
    let h = mkTxHash(1)
    check merkle_root([h]) == h

  test "merkle_root odd leaf count uses zero padding not duplicate last":
    let
      hA = mkTxHash(1)
      hB = mkTxHash(2)
      hC = mkTxHash(3)
      zero = default(Hash32)
    check merkle_root([hA, hB, hC]) == hashPair(hashPair(hA, hB), hashPair(hC, zero))
    check merkle_root([hA, hB, hC]) != merkle_root([hA, hB, hC, hC])

  test "blockId is deterministic for same header":
    let
      hx = mkTxHash(1)
      h = initHeader(
        bedrockVersion = 1'u8,
        parentBlock = default(BlockId),
        slot = SlotNumber(100),
        uncleHeaders = [],
        txHashes = [hx],
        proofOfLeadership = ProofOfLeadership(
          leaderVoucher: default(RewardVoucher),
          entropyContribution: default(ZkHash),
          proof: DefaultCompressedGroth16Proof,
          leaderKey: default(Ed25519PublicKey),
        ),
      )
    check blockId(h) == blockId(h)

  test "merkle_root directly accepts list of hashes":
    let
      txA = txWithPlaceholderProofs([createTransferOp(TransferPayload(inputs: Inputs(noteIds: @[]), outputs: Outputs(notes: @[])))])
      txB = txWithPlaceholderProofs([createSdpActiveOp(ActiveMessage(declarationId: default(DeclarationId), nonce: 1'u64, metadata: @[]))])
      hA = mantleTxHash(txA.tx).get
      hB = mantleTxHash(txB.tx).get
      hashes = [hA, hB]
    check merkle_root(hashes) == hashPair(hA, hB)
    let
      htxA = mkHashedSignedTx(txA, hA)
      htxB = mkHashedSignedTx(txB, hB)
      expectedRoot = body_root(openArray[SignedHeader]([]), merkle_root(hashes))
    check body_root(openArray[SignedHeader]([]), [htxA, htxB]) == expectedRoot
    let
      vtxA = mkValidTx(htxA)
      vtxB = mkValidTx(htxB)
    check body_root(openArray[SignedHeader]([]), [vtxA, vtxB]) ==
      body_root(openArray[SignedHeader]([]), [vtxA.hashed, vtxB.hashed])
    check merkle_root(openArray[Hash32]([])) == default(Hash32)
    check merkle_root([hA]) == hA

  test "initHeader accepts openArray[Hash32]":
    let
      hx = mkTxHash(1)
      pol = ProofOfLeadership(
        leaderVoucher: default(RewardVoucher),
        entropyContribution: default(ZkHash),
        proof: DefaultCompressedGroth16Proof,
        leaderKey: default(Ed25519PublicKey),
      )
      h = initHeader(1'u8, default(BlockId), SlotNumber(10), [], [hx], pol)
    check h.bodyRoot == body_root([], hx)

  test "initProposal accepts References directly":
    var refs: References
    let hx = mkTxHash(1)
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

  test "binary layout equivalence of transaction types":
    static:
      doAssert sizeof(typeof(default(HashedSignedMantleTx)[])) == sizeof(typeof(default(ValidSignedMantleTx).hashed[]))
      doAssert sizeof(HashedSignedMantleTx) == sizeof(ValidSignedMantleTx)
    check sizeof(typeof(default(HashedSignedMantleTx)[])) == sizeof(typeof(default(ValidSignedMantleTx).hashed[]))
    check sizeof(HashedSignedMantleTx) == sizeof(ValidSignedMantleTx)

{.pop.}
