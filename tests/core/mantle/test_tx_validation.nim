# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/strutils,
  unittest2,
  bearssl/rand,
  libp2p/crypto/ed25519/ed25519,
  libp2p/multiaddress,
  ../../../logos_chain/core/types,
  ../../../logos_chain/core/mantle/[
    operations, proofs, primitives, tx_hashing, tx_types, tx_validation, poc_verifier, utxo
  ],
  ../../../logos_chain/zk/poc,
  ./test_helpers

suite "core/mantle/tx_validation — stateless invariants":
  let rng = HmacDrbgContext.new()

  test "Transfer: rejects empty inputs":
    let tx = mkTransferTx([], [mkNote(100, 1)])
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.EmptyInputs

  test "Transfer: rejects duplicate inputs (DoubleSpend)":
    let u = mkUtxo(100, 1)
    let tx = mkTransferTx([u.id, u.id], [mkNote(200, 2)])
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.DoubleSpend

  test "Transfer: rejects zero-value output note (ZeroValueNote)":
    let u = mkUtxo(100, 1)
    let tx = mkTransferTx([u.id], [mkNote(0, 2)])
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.ZeroValueNote

  test "Transfer: accepts valid transfer":
    let u1 = mkUtxo(100, 1, opIdSeed = 1)
    let u2 = mkUtxo(100, 2, opIdSeed = 2)
    let tx = mkTransferTx([u1.id, u2.id], [mkNote(200, 3)])
    check validateMantleTxStateless(tx).isOk

  test "ChannelDeposit: rejects empty inputs":
    let op = createChannelDepositOp(ChannelDepositPayload(
      channel: mkChannelId(1),
      inputs: @[],
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfChannelDeposit, channelDepositProof: default(ZkSigProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.EmptyInputs

  test "ChannelDeposit: rejects duplicate inputs":
    let u = mkUtxo(100, 1)
    let op = createChannelDepositOp(ChannelDepositPayload(
      channel: mkChannelId(1),
      inputs: @[u.id, u.id],
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfChannelDeposit, channelDepositProof: default(ZkSigProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.DoubleSpend

  test "ChannelWithdraw: rejects empty inputs":
    let op = createChannelWithdrawOp(ChannelWithdrawPayload(
      channel: mkChannelId(1),
      inputs: @[],
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfChannelWithdraw, channelWithdrawOpProof: default(ChannelMultiSigProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.EmptyInputs

  test "ChannelWithdraw: rejects duplicate inputs":
    let u = mkUtxo(100, 1)
    let op = createChannelWithdrawOp(ChannelWithdrawPayload(
      channel: mkChannelId(1),
      inputs: @[u.id, u.id],
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfChannelWithdraw, channelWithdrawOpProof: default(ChannelMultiSigProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.DoubleSpend

  test "ChannelTransfer: rejects empty inputs":
    let op = createChannelTransferOp(ChannelTransferPayload(
      channel: mkChannelId(1),
      inputs: @[],
      outputs: @[mkNote(100, 1)],
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfChannelTransfer, channelTransferOpProof: default(ChannelMultiSigProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.EmptyInputs

  test "ChannelTransfer: rejects duplicate inputs":
    let u = mkUtxo(100, 1)
    let op = createChannelTransferOp(ChannelTransferPayload(
      channel: mkChannelId(1),
      inputs: @[u.id, u.id],
      outputs: @[mkNote(200, 2)],
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfChannelTransfer, channelTransferOpProof: default(ChannelMultiSigProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.DoubleSpend

  test "ChannelTransfer: rejects zero-value output note":
    let u = mkUtxo(100, 1)
    let op = createChannelTransferOp(ChannelTransferPayload(
      channel: mkChannelId(1),
      inputs: @[u.id],
      outputs: @[mkNote(0, 2)],
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfChannelTransfer, channelTransferOpProof: default(ChannelMultiSigProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.ZeroValueNote

  test "ChannelConfig: rejects empty keys":
    let op = createChannelConfigOp(ChannelConfigPayload(
      channel: mkChannelId(1),
      keys: @[],
      configurationThreshold: 1,
      transferThreshold: 1,
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfChannelConfig, channelConfigOpProof: default(ChannelMultiSigProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.InvalidChannelConfig

  test "ChannelConfig: rejects zero configurationThreshold":
    let kp = mkEdKeyPair(rng)
    let op = createChannelConfigOp(ChannelConfigPayload(
      channel: mkChannelId(1),
      keys: @[kp.pubkey],
      configurationThreshold: 0,
      transferThreshold: 1,
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfChannelConfig, channelConfigOpProof: default(ChannelMultiSigProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.InvalidChannelConfig

  test "ChannelConfig: rejects configurationThreshold > keys.len":
    let kp = mkEdKeyPair(rng)
    let op = createChannelConfigOp(ChannelConfigPayload(
      channel: mkChannelId(1),
      keys: @[kp.pubkey],
      configurationThreshold: 2,
      transferThreshold: 1,
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfChannelConfig, channelConfigOpProof: default(ChannelMultiSigProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.InvalidChannelConfig

  test "ChannelConfig: rejects zero transferThreshold":
    let kp = mkEdKeyPair(rng)
    let op = createChannelConfigOp(ChannelConfigPayload(
      channel: mkChannelId(1),
      keys: @[kp.pubkey],
      configurationThreshold: 1,
      transferThreshold: 0,
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfChannelConfig, channelConfigOpProof: default(ChannelMultiSigProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.InvalidChannelConfig

  test "SdpDeclare: rejects empty locators":
    let kp = mkEdKeyPair(rng)
    let op = createSdpDeclareOp(DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: kp.pubkey,
      zkId: mkZkPubKey(1),
      lockedNoteId: mkUtxo(100, 1).id,
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfSdpDeclare, declarationProof: default(ZkAndEd25519SigsProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.EmptyLocators

  test "SdpDeclare: rejects too many locators (> MaxSdpLocators)":
    let kp = mkEdKeyPair(rng)
    let validLoc = MultiAddress.init("/ip4/127.0.0.1/tcp/1234").get
    var locators = newSeq[Locator]()
    for _ in 0 .. MaxSdpLocators:
      locators.add(validLoc)
    let op = createSdpDeclareOp(DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: locators,
      providerId: kp.pubkey,
      zkId: mkZkPubKey(1),
      lockedNoteId: mkUtxo(100, 1).id,
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfSdpDeclare, declarationProof: default(ZkAndEd25519SigsProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.TooManyLocators

  test "SdpDeclare: rejects invalid multiaddress locators":
    let kp = mkEdKeyPair(rng)
    # Exceeds MaxLocatorMultiaddrBytes (329 bytes)
    let longStr = "/dns4/" & repeat('a', 350) & "/tcp/1234"
    let badLoc = MultiAddress.init(longStr).get
    let op = createSdpDeclareOp(DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[badLoc],
      providerId: kp.pubkey,
      zkId: mkZkPubKey(1),
      lockedNoteId: mkUtxo(100, 1).id,
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfSdpDeclare, declarationProof: default(ZkAndEd25519SigsProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.InvalidLocator

  test "SdpDeclare: verifies Ed25519 provider signature":
    let kp = mkEdKeyPair(rng)
    let validLoc = MultiAddress.init("/ip4/127.0.0.1/tcp/1234").get
    let op = createSdpDeclareOp(DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[validLoc],
      providerId: kp.pubkey,
      zkId: mkZkPubKey(1),
      lockedNoteId: mkUtxo(100, 1).id,
    ))
    let body = MantleTx(ops: @[op])
    let txHash = mantleTxHash(body)
    let sig = sign(kp.seckey, txHash)
    let validTx = SignedMantleTx(
      tx: body,
      opProofs: @[OpProof(
        kind: opfSdpDeclare,
        declarationProof: ZkAndEd25519SigsProof(ed25519Sig: sig, zkSig: default(ZkSigProof)),
      )],
    )
    check validateMantleTxStateless(validTx).isOk

    # Tampered signature rejects
    let badSig = sign(mkEdKeyPair(rng).seckey, txHash)
    let badTx = SignedMantleTx(
      tx: body,
      opProofs: @[OpProof(
        kind: opfSdpDeclare,
        declarationProof: ZkAndEd25519SigsProof(ed25519Sig: badSig, zkSig: default(ZkSigProof)),
      )],
    )
    let r = validateMantleTxStateless(badTx)
    check r.error == StatelessLedgerError.InvalidProof

  test "ChannelInscribe: verifies Ed25519 signer signature":
    let kp = mkEdKeyPair(rng)
    let op = createChannelInscribeOp(ChannelInscribePayload(
      channelId: mkChannelId(1),
      inscription: @[1'u8, 2, 3],
      parent: default(Hash32),
      signer: kp.pubkey,
    ))
    let body = MantleTx(ops: @[op])
    let txHash = mantleTxHash(body)
    let sig = sign(kp.seckey, txHash)
    let validTx = SignedMantleTx(
      tx: body,
      opProofs: @[OpProof(kind: opfChannelInscribe, ed25519SigProof: sig)],
    )
    check validateMantleTxStateless(validTx).isOk

    let badTx = SignedMantleTx(
      tx: body,
      opProofs: @[OpProof(kind: opfChannelInscribe, ed25519SigProof: sign(mkEdKeyPair(rng).seckey, txHash))],
    )
    let r = validateMantleTxStateless(badTx)
    check r.error == StatelessLedgerError.InvalidProof



  test "Structural: rejects ops / opProofs length mismatch":
    let u = mkUtxo(100, 1)
    let op = createTransferOp(TransferPayload(
      inputs: Inputs(noteIds: @[u.id]),
      outputs: Outputs(notes: @[mkNote(100, 2)]),
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.InvalidProof

  test "Structural: rejects mismatched proof kind":
    let u = mkUtxo(100, 1)
    let op = createTransferOp(TransferPayload(
      inputs: Inputs(noteIds: @[u.id]),
      outputs: Outputs(notes: @[mkNote(100, 2)]),
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfChannelInscribe, ed25519SigProof: default(Ed25519Signature))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.InvalidProof

  test "Structural: rejects unsupported opcode":
    let u = mkUtxo(100, 1)
    var op = createTransferOp(TransferPayload(
      inputs: Inputs(noteIds: @[u.id]),
      outputs: Outputs(notes: @[mkNote(100, 2)]),
    ))
    op.opcode = Opcode(0xFF)
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfTransfer, transferProof: default(ZkSigProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.UnsupportedOp

  test "Structural: rejects opcode / payload kind mismatch":
    let u = mkUtxo(100, 1)
    var op = createTransferOp(TransferPayload(
      inputs: Inputs(noteIds: @[u.id]),
      outputs: Outputs(notes: @[mkNote(100, 2)]),
    ))
    op.opcode = OpChannelDeposit # mismatched opcode vs Transfer payload
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfChannelDeposit, channelDepositProof: default(ZkSigProof))],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.UnsupportedOp

  test "LeaderClaim: verifies PoC Groth16 proof with verifier hook":
    let op = createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: mkZkPubKey(1),
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfLeaderClaim, proofOfClaimProof: default(ProofOfClaimProof))],
    )
    let mockAccept: ProofOfClaimVerifier = proc(
      proof: ProofOfClaimProof, public: ProofOfClaimPublic
    ): Result[bool, PocLoadError] =
      ok(true)
    let mockReject: ProofOfClaimVerifier = proc(
      proof: ProofOfClaimProof, public: ProofOfClaimPublic
    ): Result[bool, PocLoadError] =
      ok(false)

    check validateMantleTxStateless(tx, verifyProof = mockAccept).isOk
    let r = validateMantleTxStateless(tx, verifyProof = mockReject)
    check r.error == StatelessLedgerError.InvalidProof

  test "LeaderClaim: uninitialised verifier returns VerifierNotInitialised":
    let op = createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: mkZkPubKey(1),
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op]),
      opProofs: @[OpProof(kind: opfLeaderClaim, proofOfClaimProof: default(ProofOfClaimProof))],
    )
    let mockUninitialised: ProofOfClaimVerifier = proc(
      proof: ProofOfClaimProof, public: ProofOfClaimPublic
    ): Result[bool, PocLoadError] =
      err(PocLoadError.VkNotLoaded)
    let r1 = validateMantleTxStateless(tx, verifyProof = mockUninitialised)
    check r1.error == StatelessLedgerError.VerifierNotInitialised

    let r2 = validateMantleTxStateless(tx, verifyProof = nil)
    check r2.error == StatelessLedgerError.VerifierNotInitialised

  test "Multi-op transaction: accepts multiple valid operations":
    let kp = mkEdKeyPair(rng)
    let u1 = mkUtxo(100, 1, opIdSeed = 10)
    let u2 = mkUtxo(100, 2, opIdSeed = 11)
    let op1 = createTransferOp(TransferPayload(
      inputs: Inputs(noteIds: @[u1.id, u2.id]),
      outputs: Outputs(notes: @[mkNote(200, 3)]),
    ))
    let op2 = createChannelInscribeOp(ChannelInscribePayload(
      channelId: mkChannelId(1),
      inscription: @[1'u8, 2, 3],
      parent: default(Hash32),
      signer: kp.pubkey,
    ))
    let body = MantleTx(ops: @[op1, op2])
    let txHash = mantleTxHash(body)
    let sig2 = sign(kp.seckey, txHash)
    let tx = SignedMantleTx(
      tx: body,
      opProofs: @[
        OpProof(kind: opfTransfer, transferProof: default(ZkSigProof)),
        OpProof(kind: opfChannelInscribe, ed25519SigProof: sig2),
      ],
    )
    check validateMantleTxStateless(tx).isOk

  test "Multi-op transaction: rejects cross-op double-spend":
    let u1 = mkUtxo(100, 1, opIdSeed = 20)
    let op1 = createTransferOp(TransferPayload(
      inputs: Inputs(noteIds: @[u1.id]),
      outputs: Outputs(notes: @[mkNote(100, 2)]),
    ))
    let op2 = createChannelDepositOp(ChannelDepositPayload(
      channel: mkChannelId(1),
      inputs: @[u1.id], # double-spent across ops
    ))
    let tx = SignedMantleTx(
      tx: MantleTx(ops: @[op1, op2]),
      opProofs: @[
        OpProof(kind: opfTransfer, transferProof: default(ZkSigProof)),
        OpProof(kind: opfChannelDeposit, channelDepositProof: default(ZkSigProof)),
      ],
    )
    let r = validateMantleTxStateless(tx)
    check r.error == StatelessLedgerError.DoubleSpend

{.pop.}
