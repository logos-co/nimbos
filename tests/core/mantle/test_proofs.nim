# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import unittest2
import ../../../logos_chain/core/crypto/types
import ../../../logos_chain/core/mantle/proofs
import ../../../logos_chain/core/mantle/operations

suite "core/mantle/proofs":
  test "proofType maps concrete proof variants to canonical families":
    check proofType(OpProof(
      kind: opfChannelInscribe,
      ed25519SigProof: DefaultEd25519Signature,
    )) == ptEd25519Sig

    check proofType(OpProof(
      kind: opfTransfer,
      transferProof: DefaultZkSignature,
    )) == ptZkSig
    check proofType(OpProof(
      kind: opfChannelDeposit,
      channelDepositProof: DefaultZkSignature,
    )) == ptZkSig
    check proofType(OpProof(
      kind: opfSdpWithdraw,
      sdpWithdrawProof: DefaultZkSignature,
    )) == ptZkSig
    check proofType(OpProof(
      kind: opfSdpActive,
      sdpActiveProof: DefaultZkSignature,
    )) == ptZkSig

    check proofType(OpProof(
      kind: opfSdpDeclare,
      declarationProof: ZkAndEd25519SigsProof(
        zkSig: DefaultZkSignature,
        ed25519Sig: DefaultEd25519Signature,
      ),
    )) == ptZkAndEd25519Sigs

    check proofType(OpProof(
      kind: opfChannelWithdraw,
      channelWithdrawOpProof: ChannelWithdrawOpProof(signatures: @[], indexes: @[]),
    )) == ptChannelWithdraw
    check proofType(OpProof(
      kind: opfChannelConfig,
      channelConfigOpProof: ChannelWithdrawOpProof(signatures: @[], indexes: @[]),
    )) == ptChannelWithdraw

    check proofType(OpProof(
      kind: opfLeaderClaim,
      proofOfClaimProof: DefaultCompressedGroth16Proof,
    )) == ptProofOfClaim

  test "encodeOpsProofs requires proofs length == op count":
    let ops = @[
      createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[]),
      )),
      createSdpActiveOp(SdpActivePayload(
        declarationId: default(DeclarationId),
        nonce: default(Nonce),
        metadata: @[],
      )),
    ]
    let proofs = @[
      OpProof(kind: opfTransfer, transferProof: DefaultZkSignature),
      OpProof(kind: opfSdpActive, sdpActiveProof: DefaultZkSignature),
    ]
    let encoded = encodeOpsProofs(ops, proofs)
    check encoded.len == 128 + 128

  test "decodeOpsProofs roundtrips encodeOpsProofs":
    let ops = @[
      createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]),
        outputs: Outputs(notes: @[]),
      )),
      createSdpActiveOp(SdpActivePayload(
        declarationId: default(DeclarationId),
        nonce: default(Nonce),
        metadata: @[],
      )),
    ]
    let proofs = @[
      OpProof(kind: opfTransfer, transferProof: DefaultZkSignature),
      OpProof(kind: opfSdpActive, sdpActiveProof: DefaultZkSignature),
    ]
    let wire = encodeOpsProofs(ops, proofs)
    let back = decodeOpsProofs(ops, wire)
    check back.len == proofs.len
    check back[0].kind == proofs[0].kind
    check back[1].kind == proofs[1].kind

{.pop.}
