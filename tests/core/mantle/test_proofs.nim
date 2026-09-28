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
  ../../../logos_chain/core/crypto/types,
  ../../../logos_chain/core/mantle/[proofs, operations]

suite "core/mantle/proofs":
  test "the three channel multisig ops share one proof type on the wire":
    let
      proof = ChannelMultiSigProof(signatures: @[], indexes: @[])
      encBytes = encodeChannelMultiSigProof(proof.signatures, proof.indexes).get
    check encodeOpProof(
      OpProof(kind: opfChannelWithdraw, channelWithdrawOpProof: proof)).get == encBytes
    check encodeOpProof(
      OpProof(kind: opfChannelTransfer, channelTransferOpProof: proof)).get == encBytes
    check encodeOpProof(
      OpProof(kind: opfChannelConfig, channelConfigOpProof: proof)).get == encBytes
    var pos = 0
    check readOpProof(encBytes, pos, opfChannelTransfer).get.channelTransferOpProof == proof
    check pos == encBytes.len

  test "decodeOpsProofs roundtrips encodeOpsProofs and verifies wire length":
    let
      ops = @[
        createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[]),
        )),
        createSdpActiveOp(ActiveMessage(
          declarationId: default(DeclarationId),
          nonce: default(Nonce),
          metadata: @[],
        )),
      ]
      proofs = @[
        OpProof(kind: opfTransfer, transferProof: DefaultZkSignature),
        OpProof(kind: opfSdpActive, sdpActiveProof: DefaultZkSignature),
      ]
      wire = encodeOpsProofs(ops, proofs).get
    check wire.len == 128 + 128
    let back = decodeOpsProofs(ops, wire).get
    check back.len == proofs.len
    check back[0].kind == proofs[0].kind
    check back[1].kind == proofs[1].kind
    check decodeOpsProofs(ops, []).error == DecodingError.ProofCountMismatch

  test "encodeChannelMultiSigProof returns error on invalid signatures/indexes":
    let sig = DefaultEd25519Signature
    check encodeChannelMultiSigProof(@[sig], @[]).error == EncodingError.MultiSigSignaturesMismatch
    check encodeChannelMultiSigProof(@[sig, sig], @[1'u16, 1'u16]).error == EncodingError.MultiSigIndicesNonIncreasing
    check encodeChannelMultiSigProof(@[sig, sig], @[2'u16, 1'u16]).error == EncodingError.MultiSigIndicesNonIncreasing
    var tooManySigs = newSeq[Ed25519Signature](65536)
    var tooManyIdxs = newSeq[ChannelKeyIndex](65536)
    for i in 0 ..< 65536:
      tooManyIdxs[i] = ChannelKeyIndex(i)
    check encodeChannelMultiSigProof(tooManySigs, tooManyIdxs).error == EncodingError.MultiSigCountExceeded

  test "encodeOpsProofs returns error on length mismatch or proof kind mismatch":
    let transferOp = createTransferOp(TransferPayload(
      inputs: Inputs(noteIds: @[]),
      outputs: Outputs(notes: @[]),
    ))
    let transferProof = OpProof(kind: opfTransfer, transferProof: DefaultZkSignature)
    let activeProof = OpProof(kind: opfSdpActive, sdpActiveProof: DefaultZkSignature)

    check encodeOpsProofs(@[transferOp], @[]).error == EncodingError.ProofCountMismatch
    check encodeOpsProofs(@[transferOp], @[activeProof]).error == EncodingError.ProofKindMismatch
    check encodeOpsProofs(@[transferOp], @[transferProof]).isOk

{.pop.}
