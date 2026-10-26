# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  libp2p/multiaddress,
  bincode,
  ../../testutil,
  ../../../logos_chain/core/crypto/types,
  ../../../logos_chain/core/mantle/[tx_types, tx_validation]

suite "core/mantle/tx_types":
  test "bincodeDecodeHashedSignedMantleTx roundtrips empty tx":
    let
      signed = SignedMantleTx(tx: MantleTx(ops: @[]), opProofs: @[])
      wire = encodeSignedMantleTx(signed).get
      back = bincodeDecodeHashedSignedMantleTx(wire)
    check back.tx.ops.len == 0
    check back.opProofs.len == 0
    check wire.len == 1
    check wire[0] == byte(0)

  test "bincodeDecodeHashedSignedMantleTx roundtrips encodeSignedMantleTx":
    let
      signed = SignedMantleTx(
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
      wire = encodeSignedMantleTx(signed).get
      back = bincodeDecodeHashedSignedMantleTx(wire)
    check back.tx.ops.len == signed.tx.ops.len
    check back.opProofs.len == signed.opProofs.len
    check back.opProofs[0].kind == signed.opProofs[0].kind

  test "signed inscribe tx at MaxOperationDataSize round-trips and matches byteLen":
    let
      signed = SignedMantleTx(
        tx: MantleTx(ops: @[createChannelInscribeOp(ChannelInscribePayload(
          channelId: default(ChannelId),
          inscription: newSeq[byte](MaxOperationDataSize),
          parent: default(Parent),
          signer: default(Signer),
        ))]),
        opProofs: @[OpProof(
          kind: opfChannelInscribe, ed25519SigProof: DefaultEd25519Signature)],
      )
      wire = encodeSignedMantleTx(signed).get
      back = bincodeDecodeHashedSignedMantleTx(wire)
    # bincodeDecodeHashedSignedMantleTx rejects trailing bytes, so a decode
    # that succeeds consumed the whole buffer.
    check wire.len == byteLen(signed)
    check back.tx.ops.len == 1
    check back.tx.ops[0].payload.channelInscribe ==
      signed.tx.ops[0].payload.channelInscribe
    check back.opProofs.len == 1
    check back.opProofs[0].ed25519SigProof == DefaultEd25519Signature

  var sampleTxsCache: seq[SignedMantleTx]
  var hasSampleTxsCache = false

  proc sampleTxs(): seq[SignedMantleTx] =
    {.cast(gcsafe).}:
      if not hasSampleTxsCache:
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
              channel: default(ChannelId), inputs: Inputs(noteIds: @[]), metadata: @[]))]),
            opProofs: @[OpProof(kind: opfChannelDeposit, channelDepositProof: DefaultZkSignature)])
          txDepositPopulated = SignedMantleTx(
            tx: MantleTx(ops: @[createChannelDepositOp(ChannelDepositPayload(
              channel: default(ChannelId), inputs: Inputs(noteIds: @[NoteId.default, NoteId.default]), metadata: @[1'u8, 2, 3]))]),
            opProofs: @[OpProof(kind: opfChannelDeposit, channelDepositProof: DefaultZkSignature)])

          # 4. ChannelWithdraw
          txWithdraw = SignedMantleTx(
            tx: MantleTx(ops: @[createChannelWithdrawOp(ChannelWithdrawPayload(
              channel: default(ChannelId), inputs: Inputs(noteIds: @[NoteId.default])))]),
            opProofs: @[OpProof(kind: opfChannelWithdraw, channelWithdrawOpProof: ChannelMultiSigProof(
              signatures: @[DefaultEd25519Signature, DefaultEd25519Signature],
              indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(1)]))])

          # 5. ChannelTransfer
          txChannelTransfer = SignedMantleTx(
            tx: MantleTx(ops: @[createChannelTransferOp(ChannelTransferPayload(
              channel: default(ChannelId), inputs: Inputs(noteIds: @[NoteId.default]),
              outputs: Outputs(notes: @[Note(value: 50, zkPublicKey: ZkPublicKey.default)])))]),
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
              declarationId: default(DeclarationId), nonce: 42))]),
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

        sampleTxsCache = @[
          txTransferEmpty, txTransferPopulated,
          txInscribeEmpty, txInscribeData,
          txDepositEmpty, txDepositPopulated,
          txWithdraw, txChannelTransfer, txChannelConfig,
          txSdpDeclare, txSdpWithdraw, txSdpActive, txLeaderClaim,
          txMultiOp,
        ]
        hasSampleTxsCache = true
      sampleTxsCache

  test "byteLen parity across all 10 operation and proof variants":
    let allTxs = sampleTxs()
    for tx in allTxs:
      let enc = encodeSignedMantleTx(tx).get
      check byteLen(tx) == enc.len
      let htx = createHashedSignedMantleTx(tx).get
      check byteLen(htx) == enc.len
      check encodeSignedMantleTx(htx).get == enc
      check htx.tx.ops.len == tx.tx.ops.len
      check htx.opProofs.len == tx.opProofs.len
    let
      gtx = testValidGenesisTx()
      vtx = ValidSignedMantleTx(gtx)
    check byteLen(vtx) == encodeSignedMantleTx(vtx.hashed).get.len
    check encodeSignedMantleTx(vtx.hashed).get == encodeSignedMantleTx(vtx.hashed.signedTx).get
    check vtx.tx.ops.len == vtx.hashed.tx.ops.len
    check vtx.opProofs.len == vtx.hashed.opProofs.len
    check byteLen(gtx) == encodeSignedMantleTx(gtx.hashed).get.len
    check encodeSignedMantleTx(gtx.hashed).get == encodeSignedMantleTx(gtx.hashed.signedTx).get
    check gtx.tx.ops.len == vtx.tx.ops.len
    check gtx.opProofs.len == vtx.opProofs.len

  test "encodeSignedMantleTx returns error on proof count mismatch":
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[
        createTransferOp(TransferPayload(inputs: Inputs(noteIds: @[]), outputs: Outputs(notes: @[])))
      ]),
      opProofs: @[]
    )
    check encodeSignedMantleTx(tx).error == EncodingError.ProofCountMismatch

  test "bijective wire-slice roundtrip and hash parity across all operation variants (D6)":
    for tx in sampleTxs():
      let
        wire = encodeSignedMantleTx(tx).get
        decodedHtx = bincodeDecodeHashedSignedMantleTx(wire)
        txWireLen = byteLen(decodedHtx.tx)
      check txWireLen > 0
      check encodeMantleTx(decodedHtx.tx).get == wire.toOpenArray(0, txWireLen - 1)
      let bincodeHtx = decode(encode(wire), HashedSignedMantleTx)
      check bincodeHtx.hash == mantleTxHash(tx.tx).get
      check decodedHtx.hash == mantleTxHash(tx.tx).get
      check decodedHtx.tx.ops.len == tx.tx.ops.len
      check decodedHtx.opProofs.len == tx.opProofs.len

  test "decode rejects non-canonical field element >= curve modulus (D6)":
    let txTransferPopulated = sampleTxs()[1]
    var badWire = encodeSignedMantleTx(txTransferPopulated).get
    # In txTransferPopulated:
    # byte 0: ops count = 1
    # byte 1: opcode = Opcode.transfer
    # byte 2: inputs count = 2
    # bytes 3..34: first NoteId (FieldElement)
    for i in 3 ..< 35:
      badWire[i] = 0xFF'u8
    expect BincodeError:
      discard bincodeDecodeHashedSignedMantleTx(badWire)
    let badBincodeWire = encode(badWire)
    expect BincodeError:
      discard decode(badBincodeWire, HashedSignedMantleTx)

  test "HashedSignedMantleTx bincode roundtrip and nil rejection":
    let cfg = standard()
    for tx in sampleTxs():
      let
        htx = createHashedSignedMantleTx(tx).get
        wire = encode(htx, cfg)
        back = decode(wire, HashedSignedMantleTx, cfg)
      check back.hash == htx.hash
      check back.signedTx.tx.ops.len == htx.signedTx.tx.ops.len
      check back.signedTx.opProofs.len == htx.signedTx.opProofs.len
    let nilHtx: HashedSignedMantleTx = nil
    expect BincodeError:
      discard encode(nilHtx, cfg)

  test "createGenesisHtx creates HashedSignedMantleTx with precomputed hash":
    let
      gtx = testGenesisHtx().signedTx
      htx = createGenesisHtx(gtx).get
    check htx.signedTx.tx.ops.len == gtx.tx.ops.len
    check htx.signedTx.opProofs.len == gtx.opProofs.len
    check htx.hash == mantleTxHash(gtx.tx).get

  test "bincodeDecodeHashedSignedMantleTx rejects empty input":
    expect BincodeError:
      discard bincodeDecodeHashedSignedMantleTx(@[])

  test "bincodeDecodeHashedSignedMantleTx rejects truncated wire slice":
    let
      sample = sampleTxs()[0]
      wire = encodeSignedMantleTx(sample).get
    expect BincodeError:
      discard bincodeDecodeHashedSignedMantleTx(wire.toOpenArray(0, wire.len div 2))

  test "bincodeDecodeHashedSignedMantleTx rejects missing proofs when ops present":
    let
      sample = sampleTxs()[0]
      txWire = encodeMantleTx(sample.tx).get
    expect BincodeError:
      discard bincodeDecodeHashedSignedMantleTx(txWire)

  test "bincodeDecodeHashedSignedMantleTx rejects trailing bytes":
    var wire = encodeSignedMantleTx(sampleTxs()[0]).get
    wire.add(0xFF'u8)
    expect BincodeError:
      discard bincodeDecodeHashedSignedMantleTx(wire)

  test "bincodeDecodeHashedSignedMantleTx rejects zero ops with trailing bytes":
    expect BincodeError:
      discard bincodeDecodeHashedSignedMantleTx(@[0'u8, 1'u8])

  test "bincodeDecodeHashedSignedMantleTx rejects unsupported opcode":
    expect BincodeError:
      discard bincodeDecodeHashedSignedMantleTx(@[1'u8, 0xFF'u8])

  test "bincodeDecodeHashedSignedMantleTx rejects extra proof in proof segment":
    let sample = sampleTxs()[0]
    var wire = encodeSignedMantleTx(sample).get
    let extraProof = encodeOpProof(sample.opProofs[0]).get
    wire.add(extraProof)
    expect BincodeError:
      discard bincodeDecodeHashedSignedMantleTx(wire)

  test "bincodeDecodeHashedSignedMantleTx rejects truncated proof segment":
    let
      sample = sampleTxs()[0]
      wire = encodeSignedMantleTx(sample).get
    expect BincodeError:
      discard bincodeDecodeHashedSignedMantleTx(wire.toOpenArray(0, wire.high - 1))

  test "bincodeDecodeHashedSignedMantleTx rejects fewer proofs than ops in multi-op tx":
    let
      multiTx = sampleTxs()[^1]
      wire = encodeSignedMantleTx(multiTx).get
      txWireLen = byteLen(multiTx.tx)
      singleProof = encodeOpProof(multiTx.opProofs[0]).get
    var truncatedProofsWire = wire[0 ..< txWireLen]
    truncatedProofsWire.add(singleProof)
    expect BincodeError:
      discard bincodeDecodeHashedSignedMantleTx(truncatedProofsWire)

{.pop.}
