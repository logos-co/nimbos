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
  libp2p/multiaddress,
  ../../../logos_chain/core/crypto/types,
  ../../../logos_chain/core/mantle/tx_types

suite "core/mantle/tx_types":
  test "decodeMantleTx roundtrips encodeMantleTx":
    let tx = MantleTx(ops: @[])
    let wire = encodeMantleTx(tx)
    let back = decodeMantleTx(wire)
    check back.ops.len == tx.ops.len
    check wire.len == 1
    check wire[0] == byte(0)

  test "decodeSignedMantleTx roundtrips encodeSignedMantleTx":
    let signed = SignedMantleTx(
      tx: MantleTx(
        ops: @[
          createTransferOp(TransferPayload(
            inputs: Inputs(noteIds: @[]),
            outputs: Outputs(notes: @[]),
          )),
        ],
      ),
      opProofs: @[
        OpProof(kind: opfTransfer, transferProof: DefaultZkSignature),
      ],
    )
    let
      wire = encodeSignedMantleTx(signed)
      back = decodeSignedMantleTx(wire)
    check back.tx.ops.len == signed.tx.ops.len
    check back.opProofs.len == signed.opProofs.len
    check back.opProofs[0].kind == signed.opProofs[0].kind

  test "byteLen parity across all 10 operation and proof variants":
    let
      # 1. Transfer
      txTransferEmpty = SignedMantleTx(
        tx: MantleTx(ops: @[createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]), outputs: Outputs(notes: @[])))]),
        opProofs: @[OpProof(kind: opfTransfer, transferProof: DefaultZkSignature)])
      txTransferPopulated = SignedMantleTx(
        tx: MantleTx(ops: @[createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[NoteId.default, NoteId.default]),
          outputs: Outputs(notes: @[Note(value: 100, zkPublicKey: ZkPublicKey.default), Note(value: 200, zkPublicKey: ZkPublicKey.default)])))]),
        opProofs: @[OpProof(kind: opfTransfer, transferProof: DefaultZkSignature)])

      # 2. ChannelInscribe
      txInscribeEmpty = SignedMantleTx(
        tx: MantleTx(ops: @[createChannelInscribeOp(ChannelInscribePayload(
          channelId: default(ChannelId), inscription: @[], parent: default(Parent), signer: default(Signer)))]),
        opProofs: @[OpProof(kind: opfChannelInscribe, ed25519SigProof: DefaultEd25519Signature)])
      txInscribeData = SignedMantleTx(
        tx: MantleTx(ops: @[createChannelInscribeOp(ChannelInscribePayload(
          channelId: default(ChannelId), inscription: @[1'u8, 2, 3, 4, 5], parent: default(Parent), signer: default(Signer)))]),
        opProofs: @[OpProof(kind: opfChannelInscribe, ed25519SigProof: DefaultEd25519Signature)])

      # 3. ChannelDeposit
      txDepositEmpty = SignedMantleTx(
        tx: MantleTx(ops: @[createChannelDepositOp(ChannelDepositPayload(
          channel: default(ChannelId), inputs: @[], metadata: @[]))]),
        opProofs: @[OpProof(kind: opfChannelDeposit, channelDepositProof: DefaultZkSignature)])
      txDepositPopulated = SignedMantleTx(
        tx: MantleTx(ops: @[createChannelDepositOp(ChannelDepositPayload(
          channel: default(ChannelId), inputs: @[NoteId.default, NoteId.default], metadata: @[1'u8, 2, 3]))]),
        opProofs: @[OpProof(kind: opfChannelDeposit, channelDepositProof: DefaultZkSignature)])

      # 4. ChannelWithdraw
      txWithdraw = SignedMantleTx(
        tx: MantleTx(ops: @[createChannelWithdrawOp(ChannelWithdrawPayload(
          channel: default(ChannelId), inputs: @[NoteId.default]))]),
        opProofs: @[OpProof(kind: opfChannelWithdraw, channelWithdrawOpProof: ChannelMultiSigProof(
          signatures: @[DefaultEd25519Signature, DefaultEd25519Signature],
          indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(1)]))])

      # 5. ChannelTransfer
      txChannelTransfer = SignedMantleTx(
        tx: MantleTx(ops: @[createChannelTransferOp(ChannelTransferPayload(
          channel: default(ChannelId), inputs: @[NoteId.default],
          outputs: @[Note(value: 50, zkPublicKey: ZkPublicKey.default)]))]),
        opProofs: @[OpProof(kind: opfChannelTransfer, channelTransferOpProof: ChannelMultiSigProof(
          signatures: @[DefaultEd25519Signature], indexes: @[ChannelKeyIndex(0)]))])

      # 6. ChannelConfig
      txChannelConfig = SignedMantleTx(
        tx: MantleTx(ops: @[createChannelConfigOp(ChannelConfigPayload(
          channel: default(ChannelId),
          keys: @[Ed25519PublicKey.default, Ed25519PublicKey.default],
          postingTimeframe: 10, postingTimeout: 20,
          configurationThreshold: 2, transferThreshold: 1))]),
        opProofs: @[OpProof(kind: opfChannelConfig, channelConfigOpProof: ChannelMultiSigProof(
          signatures: @[DefaultEd25519Signature], indexes: @[ChannelKeyIndex(0)]))])

      # 7. SdpDeclare
      txSdpDeclare = SignedMantleTx(
        tx: MantleTx(ops: @[createSdpDeclareOp(DeclarationMessage(
          serviceType: ServiceType.bn,
          locators: @[MultiAddress.init("/ip4/127.0.0.1/tcp/1234").get, MultiAddress.init("/ip4/10.0.0.1/tcp/8080").get],
          providerId: default(ProviderId), zkId: default(ZkId), lockedNoteId: default(LockedNoteId)))]),
        opProofs: @[OpProof(kind: opfSdpDeclare, declarationProof: ZkAndEd25519SigsProof(
          zkSig: DefaultZkSignature, ed25519Sig: DefaultEd25519Signature))])

      # 8. SdpWithdraw
      txSdpWithdraw = SignedMantleTx(
        tx: MantleTx(ops: @[createSdpWithdrawOp(WithdrawMessage(
          declarationId: default(DeclarationId), nonce: 42, lockedNoteId: default(LockedNoteId)))]),
        opProofs: @[OpProof(kind: opfSdpWithdraw, sdpWithdrawProof: DefaultZkSignature)])

      # 9. SdpActive
      txSdpActive = SignedMantleTx(
        tx: MantleTx(ops: @[createSdpActiveOp(ActiveMessage(
          declarationId: default(DeclarationId), nonce: 42, metadata: @[7'u8, 8, 9]))]),
        opProofs: @[OpProof(kind: opfSdpActive, sdpActiveProof: DefaultZkSignature)])

      # 10. LeaderClaim
      txLeaderClaim = SignedMantleTx(
        tx: MantleTx(ops: @[createLeaderClaimOp(LeaderClaimPayload(
          rewardsRoot: default(RewardsRoot), voucherNullifier: default(VoucherNullifier), publicKey: default(ZkPublicKey)))]),
        opProofs: @[OpProof(kind: opfLeaderClaim, proofOfClaimProof: DefaultCompressedGroth16Proof)])

      # Multi-op combo
      txMultiOp = SignedMantleTx(
        tx: MantleTx(ops: @[
          createTransferOp(TransferPayload(inputs: Inputs(noteIds: @[NoteId.default]), outputs: Outputs(notes: @[]))),
          createChannelInscribeOp(ChannelInscribePayload(channelId: default(ChannelId), inscription: @[1'u8, 2], parent: default(Parent), signer: default(Signer))),
          createSdpWithdrawOp(WithdrawMessage(declarationId: default(DeclarationId), nonce: 1, lockedNoteId: default(LockedNoteId)))
        ]),
        opProofs: @[
          OpProof(kind: opfTransfer, transferProof: DefaultZkSignature),
          OpProof(kind: opfChannelInscribe, ed25519SigProof: DefaultEd25519Signature),
          OpProof(kind: opfSdpWithdraw, sdpWithdrawProof: DefaultZkSignature),
        ])

    let allTxs = [
      txTransferEmpty, txTransferPopulated,
      txInscribeEmpty, txInscribeData,
      txDepositEmpty, txDepositPopulated,
      txWithdraw, txChannelTransfer, txChannelConfig,
      txSdpDeclare, txSdpWithdraw, txSdpActive, txLeaderClaim,
      txMultiOp,
    ]

    for tx in allTxs:
      check byteLen(tx) == encodeSignedMantleTx(tx).len
      check byteLen(ValidSignedMantleTx(tx)) == encodeSignedMantleTx(tx).len

{.pop.}
