# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[os, strutils, tables],
  unittest2,
  results,
  stew/io2,
  bearssl/rand,
  libp2p/crypto/ed25519/ed25519,
  ../../logos_chain/ledger/
    [balance, cryptarchia_state, ledger, types],
  ../../logos_chain/ledger/sdp/[ops, registry, state],
  ../../logos_chain/core/mantle/
    [primitives, operations, proofs, tx_hashing, tx_types, utxo],
  ../../logos_chain/core/types,
  ../../logos_chain/zk/pol,
  ../zk/[snarkjs_helpers, zksign_helpers],
  ./sdp/test_helpers,
  ../core/mantle/test_helpers,
  ../testutil

func initLedger(
    id: TestId,
    state: LedgerState,
    config: LedgerConfig = LedgerConfig(),
    leaderProofVerifier: LeaderProofVerifier = mockVerifyLeaderProof,
): Ledger[TestId] =
  Ledger[TestId].init(id, state, config, leaderProofVerifier)

from ./test_helpers import testLedgerConfig

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  fixtureVk = testsDir / "../fixtures/pol/verification_key.json"
  zksignFixtureDir = testsDir / "../fixtures/zksign"
  zksignFixtureVk = zksignFixtureDir / "verification_key.json"
  transferProofPath = zksignFixtureDir / "proof.json"

proc mkProvider(seed: byte): ProviderId =
  var bytes: array[EdPublicKeySize, byte]
  bytes[0] = seed
  var key: ProviderId
  doAssert key.init(bytes)
  key

proc mkState(utxos: openArray[Utxo]): LedgerState =
  ## Epoch-seeded genesis-style state under `testLedgerConfig` (zero nonce);
  ## the bare, un-seeded constructor no longer exists.
  LedgerState.fromUtxos(
    utxos, default(FieldElement), testSdpRegistry(), testLedgerConfig
  ).expect("seed")

proc mkFixtureTransferTx(input: Utxo): SignedMantleTx =
  ## The exact tx shape the committed zksign fixture proof was generated for.
  var tx = mkTransferTx(
    [input.id], [Note(value: 100, zkPublicKey: default(ZkPublicKey))])
  tx.opProofs[0].transferProof = loadProof(transferProofPath)
  tx

suite "LedgerState constructors and reads":
  test "fromUtxos with empty seq → empty state":
    let s = mkState(@[])
    check s.latestUtxos.len == 0

  test "fromUtxos with N utxos → state populated":
    let
      u1 = mkUtxo(value = 50, pkSeed = 1)
      u2 = mkUtxo(value = 100, pkSeed = 2)
      s = mkState([u1, u2])
    check s.latestUtxos.len == 2
    check s.latestUtxos.contains(u1.id)
    check s.latestUtxos.contains(u2.id)

suite "tryApplyHeader":
  test "genesis-sentinel proof returns state unchanged":
    let
      u = mkUtxo()
      s0 = mkState([u])
      r = s0.tryApplyHeader(slot = 1'u64, proof = mkProof(), cfg = testLedgerConfig)
    check r.isOk
    check r.get.latestUtxos == s0.latestUtxos

  test "returns VerifierNotInitialised when VK singleton missing":
    pol.resetVkForTesting()
    let s0 = mkState([mkUtxo()])
    var bad = mkProof()
    bad.proof[0] = 0x01  # break the genesis sentinel so verify is invoked
    let r = s0.tryApplyHeader(slot = 1'u64, proof = bad, cfg = testLedgerConfig)
    check r.error == VerifierNotInitialised

  test "returns InvalidProofOfLeadership when verifier rejects":
    pol.resetVkForTesting()
    let vkText = readAllChars(fixtureVk).valueOr:
      check false
      return
    let vk = parseVk(vkText).valueOr:
      check false
      return
    check pol.initVk(vk).isOk

    let s0 = mkState([mkUtxo()])
    var bad = mkProof()
    bad.proof[0] = 0x01  # bit-pattern can't be a valid compressed G1 point
    let r = s0.tryApplyHeader(slot = 1'u64, proof = bad, cfg = testLedgerConfig)
    check r.error == InvalidProofOfLeadership

suite "tryApplyTx — channel ops":
  proc mkChannelState(
      utxos: openArray[Utxo],
      cid: ChannelId,
      key: Ed25519PublicKey,
      owned: openArray[Utxo],
  ): LedgerState =
    ## Ledger seeded with a 1-of-1 channel that already owns `owned`.
    var s = mkState(utxos)
    s.mantleLedger = MantleState.init().tryApplyChannelConfig(
      ChannelConfigPayload(
        channel: cid,
        keys: @[key],
        configurationThreshold: 1,
        transferThreshold: 1,
      ),
      # A just-in-time created channel has no accredited keys to check the
      # proof against, so the tx hash is immaterial here.
      ChannelMultiSigProof(), default(Hash32), blockSlot = 0'u64,
    ).expect("valid config")
    for u in owned:
      s.mantleLedger.channelNotes =
        s.mantleLedger.channelNotes.registerChannelNote(u.id, cid)
          .expect("fresh note")
    s

  test "ChannelWithdraw contributes nothing to the transaction balance":
    let
      rng = HmacDrbgContext.new()
      kp = mkEdKeyPair(rng)
      cid = mkChannelId(2)
      note = mkUtxo(value = 100, pkSeed = 1)
      s0 = mkChannelState([note], cid, kp.pubkey, [note])
      body = MantleTx(ops: @[createChannelWithdrawOp(
        ChannelWithdrawPayload(channel: cid, inputs: @[note.id]))])
      txHash = mantleTxHash(body)
      tx = SignedMantleTx(
        tx: body,
        opProofs: @[OpProof(
          kind: opfChannelWithdraw,
          channelWithdrawOpProof: ChannelMultiSigProof(
            signatures: @[sign(kp.seckey, txHash)],
            indexes: @[ChannelKeyIndex(0)]))],
      )
      r = s0.tryApplyTx(
        ValidSignedMantleTx(tx), epoch = EpochNumber(0), slot = 0'u64, verifyPoq = acceptAllPoq)
    check r.isOk
    let res = r.get
    # Bridged funds never enter or leave the UTXO set, so a channel op can
    # never fund its own fees — a Transfer op in the same tx must.
    check res.balance == Balance.zero
    check res.executionGas == Gas(56)
    check res.state.latestUtxos.len == 1
    check res.state.latestUtxos.contains(note.id)
    check res.state.mantleLedger.channelNotes.isEmpty

  test "ChannelTransfer keeps the balance at zero while rewriting the notes":
    let
      rng = HmacDrbgContext.new()
      kp = mkEdKeyPair(rng)
      cid = mkChannelId(3)
      note = mkUtxo(value = 100, pkSeed = 1)
      reassigned = mkNote(100, pkSeed = 2)
      s0 = mkChannelState([note], cid, kp.pubkey, [note])
      op = ChannelTransferPayload(
        channel: cid, inputs: @[note.id], outputs: @[reassigned])
      body = MantleTx(ops: @[createChannelTransferOp(op)])
      txHash = mantleTxHash(body)
      tx = SignedMantleTx(
        tx: body,
        opProofs: @[OpProof(
          kind: opfChannelTransfer,
          channelTransferOpProof: ChannelMultiSigProof(
            signatures: @[sign(kp.seckey, txHash)],
            indexes: @[ChannelKeyIndex(0)]))],
      )
      r = s0.tryApplyTx(
        ValidSignedMantleTx(tx), epoch = EpochNumber(0), slot = 0'u64, verifyPoq = acceptAllPoq)
    check r.isOk
    let
      res = r.get
      minted = Utxo(opId: opId(op), outputIndex: 0, note: reassigned)
    check res.balance == Balance.zero
    check res.executionGas == Gas(56)
    check not res.state.latestUtxos.contains(note.id)
    check res.state.latestUtxos.contains(minted.id)
    check res.state.mantleLedger.channelNotes.isChannelNoteOf(minted.id, cid)

  test "a regular Transfer cannot spend a channel note → ChannelNoteSpend":
    let
      rng = HmacDrbgContext.new()
      kp = mkEdKeyPair(rng)
      cid = mkChannelId(4)
      note = mkUtxo(value = 100, pkSeed = 1)
      s0 = mkChannelState([note], cid, kp.pubkey, [note])
      tx = mkTransferTx([note.id], [mkNote(100, pkSeed = 2)])
      r = s0.tryApplyTx(
        ValidSignedMantleTx(tx), epoch = EpochNumber(0), slot = 0'u64, verifyPoq = acceptAllPoq)
    check r.error == ChannelNoteSpend

suite "Ledger[Id] map ops":
  test "init seeds one (id, state); hasState returns true for seeded, false for missing":
    let
      seed = mkState(@[mkUtxo()])
      id = mkId(0x01)
      l = initLedger(id, seed, testLedgerConfig)
    check l.hasState(id)
    check not l.hasState(mkId(0x02))

  test "commitUpdate overwrites":
    var l = initLedger(mkId(0x01), mkState(@[]), testLedgerConfig)
    let
      id2 = mkId(0x02)
      st2 = mkState(@[mkUtxo(value = 7, pkSeed = 7)])
    l.commitUpdate(id2, st2)
    check l.state(id2).isSome
    check l.state(id2).get.latestUtxos.len == 1

  test "pruneStateAt removes existing, returns true; missing returns false":
    var l = initLedger(mkId(0x01), mkState(@[]), testLedgerConfig)
    check l.pruneStateAt(mkId(0x01)) == true
    check l.state(mkId(0x01)).isNone
    check l.pruneStateAt(mkId(0x99)) == false

suite "prepareUpdate — no-verify paths":
  test "parent missing → ParentNotFound":
    let
      l = initLedger(mkId(0x01), mkState(@[]), testLedgerConfig)
      r = l.prepareUpdate(
        id = mkId(0x02),
        parentId = mkId(0xff),
        slot = 1'u64,
        proof = mkProof(),
        txs = @[],
      )
    check r.isErr
    check r.error == ParentNotFound

  test "empty tx list → state unchanged, no commit":
    let
      parent = mkState(@[mkUtxo()])
      id0 = mkId(0x01)
      l = initLedger(id0, parent, testLedgerConfig)
      id1 = mkId(0x02)
      r = l.prepareUpdate(
        id = id1,
        parentId = id0,
        slot = 1'u64,
        proof = mkProof(),
        txs = @[],
      )
    check r.isOk
    let prepared = r.get
    check prepared.id == id1
    check prepared.state.latestUtxos == parent.latestUtxos
    check l.state(id1).isNone # not committed

suite "tryApplyTx — happy path (Rust-generated fixture)":
  # Uses a pre-generated proof tied to this exact tx shape. Any change to
  # the inputs/outputs/values requires regenerating the fixture.
  setup:
    check installZksignVk(zksignFixtureVk)

  test "single OpTransfer (balanced) verifies and clears the input":
    let
      input = mkUtxoWithPk(mkRealZkPubKey(1), value = 100)
      s0 = mkState([input])
      r = s0.tryApplyTx(
        ValidSignedMantleTx(mkFixtureTransferTx(input)), epoch = EpochNumber(0), slot = 0'u64,
        verifyPoq = acceptAllPoq)
    check r.isOk

    let res = r.get
    check res.balance == Balance.zero
    check res.state.latestUtxos.len == 1
    check not res.state.latestUtxos.contains(input.id)

  test "tx application preserves the epoch tracker and SDP registry":
    # Guards against ops rebuilding LedgerState and resetting omitted fields.
    # Channel deposit/withdraw need a tx-level fixture (no Nim-side prover).
    let
      input = mkUtxoWithPk(mkRealZkPubKey(1), value = 100)
      lockedElsewhere = mkUtxo(value = 50, pkSeed = 8)
    var s0 = mkState([input, lockedElsewhere])
    let declaration = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: mkProvider(8),
      lockedNoteId: lockedElsewhere.id,
      zkId: lockedElsewhere.note.zkPublicKey,
    )
    discard installTestDeclaration(s0.sdp, declaration, epoch = 1)
    let r = s0.tryApplyTx(
      ValidSignedMantleTx(mkFixtureTransferTx(input)), epoch = EpochNumber(0), slot = 0'u64,
      verifyPoq = acceptAllPoq)
    check r.isOk
    let res = r.get
    check res.state.epochs == s0.epochs
    check declarationId(declaration) in res.state.sdp.state.declarations

# Suites below need a valid `OpProof` per transfer op — i.e. a zksign proof
# generated for that op's input pks + tx hash. nimbos has no Nim-side prover
# yet (only the verifier); re-enable these tests once a prover lands.
when false:
  suite "tryApplyTx — multi-op":
    test "two balanced Transfer ops → balance == 0, both applied":
      let
        in1 = mkUtxo(value = 100, pkSeed = 1)
        in2 = mkUtxo(value = 50, pkSeed = 2)
        s0 = mkState([in1, in2])
        op1 = createTransferOp(
          TransferPayload(
            inputs: Inputs(noteIds: @[in1.id]),
            outputs: Outputs(notes: @[mkNote(100, pkSeed = 3)]),
          )
        )
        op2 = createTransferOp(
          TransferPayload(
            inputs: Inputs(noteIds: @[in2.id]),
            outputs: Outputs(notes: @[mkNote(50, pkSeed = 4)]),
          )
        )
        tx = SignedMantleTx(
          tx:
            MantleTx(ops: @[op1, op2]),
          opProofs:
            @[
              OpProof(kind: opfTransfer, transferProof: default(ZkSigProof)),
              OpProof(kind: opfTransfer, transferProof: default(ZkSigProof)),
            ],
        )
        r = s0.tryApplyTx(
          tx, epoch = EpochNumber(0), slot = 0'u64, verifyPoq = acceptAllPoq)
      check r.isOk
      let res = r.get
      check res.balance == Balance.zero
      check res.state.latestUtxos.len == 2
      check not res.state.latestUtxos.contains(in1.id)
      check not res.state.latestUtxos.contains(in2.id)

    test "two ops, second has wrong proof kind → InvalidTxProof":
      let
        in1 = mkUtxo(value = 100, pkSeed = 1)
        in2 = mkUtxo(value = 50, pkSeed = 2)
        s0 = mkState([in1, in2])
        op1 = createTransferOp(
          TransferPayload(
            inputs: Inputs(noteIds: @[in1.id]),
            outputs: Outputs(notes: @[mkNote(100, pkSeed = 3)]),
          )
        )
        op2 = createTransferOp(
          TransferPayload(
            inputs: Inputs(noteIds: @[in2.id]),
            outputs: Outputs(notes: @[mkNote(50, pkSeed = 4)]),
          )
        )
        tx = SignedMantleTx(
          tx:
            MantleTx(ops: @[op1, op2]),
          opProofs:
            @[
              OpProof(kind: opfTransfer, transferProof: default(ZkSigProof)),
              OpProof(kind: opfChannelInscribe, ed25519SigProof: default(Ed25519SigProof)),
            ],
        )
        r = s0.tryApplyTx(
          tx, epoch = EpochNumber(0), slot = 0'u64, verifyPoq = acceptAllPoq)
      check r.isErr
      check r.error == InvalidTxProof

  suite "tryApplyTxns":
    test "balanced tx → state advances":
      let
        input = mkUtxo(value = 100, pkSeed = 1)
        s0 = mkState([input])
        tx = mkTransferTx([input.id], [mkNote(100, pkSeed = 2)])
        r = s0.tryApplyTxns([ValidSignedMantleTx(tx)], slot = 0'u64, verifyPoq = acceptAllPoq)
      check r.isOk
      check r.get.latestUtxos.len == 1

    test "underspending (output > input) → InsufficientBalance":
      let
        input = mkUtxo(value = 100, pkSeed = 1)
        s0 = mkState([input])
        tx = mkTransferTx([input.id], [mkNote(60, pkSeed = 2), mkNote(50, pkSeed = 3)])
          # sum 110 > input 100
        r = s0.tryApplyTxns([ValidSignedMantleTx(tx)], slot = 0'u64, verifyPoq = acceptAllPoq)
      check r.isErr
      check r.error == InsufficientBalance

    test "surplus below fee (input > output) → InsufficientBalance":
      let
        input = mkUtxo(value = 100, pkSeed = 1)
        s0 = mkState([input])
        tx = mkTransferTx([input.id], [mkNote(50, pkSeed = 2)]) # surplus 50 < fee
        r = s0.tryApplyTxns([ValidSignedMantleTx(tx)], slot = 0'u64, verifyPoq = acceptAllPoq)
      check r.isErr
      check r.error == InsufficientBalance

  suite "prepareUpdate — verify paths":
    test "happy path with one transfer + commit":
      var l = initLedger(
        mkId(0x01), mkState([mkUtxo(value = 100, pkSeed = 1)]), testLedgerConfig
      )
      let
        input = mkUtxo(value = 100, pkSeed = 1)
        tx = mkTransferTx([input.id], [mkNote(100, pkSeed = 2)])
        r = l.prepareUpdate(
          id = mkId(0x02),
          parentId = mkId(0x01),
          slot = 1'u64,
          proof = mkProof(),
          txs = [ValidSignedMantleTx(tx)],
        )
      check r.isOk
      let prepared = r.get
      l.commitUpdate(prepared.id, prepared.state)
      check l.state(mkId(0x02)).isSome
      check l.state(mkId(0x02)).get.latestUtxos.len == 1
      check not l.state(mkId(0x02)).get.latestUtxos.contains(input.id)

    test "surplus below fee → InsufficientBalance":
      let
        input = mkUtxo(value = 100, pkSeed = 1)
        l = initLedger(mkId(0x01), mkState([input]), testLedgerConfig)
        tx = mkTransferTx([input.id], [mkNote(50, pkSeed = 2)]) # 100 in, 50 out
        r = l.prepareUpdate(
          id = mkId(0x02),
          parentId = mkId(0x01),
          slot = 1'u64,
          proof = mkProof(),
          txs = [ValidSignedMantleTx(tx)],
        )
      check r.isErr
      check r.error == InsufficientBalance

    test "multi-block IBD: 3 prepare+commit cycles":
      # Walks the same prepare→commit sequence the chain module will eventually
      # drive. Each block consumes the prior block's output as its input.
      var l = initLedger(
        mkId(0x00), mkState([mkUtxo(value = 100, pkSeed = 1)]), testLedgerConfig
      )
      # Block 1: spend genesis utxo into a new note (pk=2)
      let
        input1 = mkUtxo(value = 100, pkSeed = 1)
        tx1 = mkTransferTx([input1.id], [mkNote(100, pkSeed = 2)])
        r1 = l.prepareUpdate(
          id = mkId(0x01),
          parentId = mkId(0x00),
          slot = 1'u64,
          proof = mkProof(),
          txs = [ValidSignedMantleTx(tx1)],
        )
      check r1.isOk
      l.commitUpdate(r1.get.id, r1.get.state)

      let
        tx1OpId = opId(
          TransferPayload(
            inputs: Inputs(noteIds: @[input1.id]),
            outputs: Outputs(notes: @[mkNote(100, pkSeed = 2)]),
          )
        )
        utxoAfter1 = Utxo(
          opId: tx1OpId, outputIndex: 0, note: mkNote(100, pkSeed = 2)
        )
      check l.state(mkId(0x01)).get.latestUtxos.contains(utxoAfter1.id)

      let
        tx2 = mkTransferTx([utxoAfter1.id], [mkNote(100, pkSeed = 3)])
        r2 = l.prepareUpdate(
          id = mkId(0x02),
          parentId = mkId(0x01),
          slot = 2'u64,
          proof = mkProof(),
          txs = [ValidSignedMantleTx(tx2)],
        )
      check r2.isOk
      l.commitUpdate(r2.get.id, r2.get.state)

      let
        tx2OpId = opId(
          TransferPayload(
            inputs: Inputs(noteIds: @[utxoAfter1.id]),
            outputs: Outputs(notes: @[mkNote(100, pkSeed = 3)]),
          )
        )
        utxoAfter2 = Utxo(
          opId: tx2OpId, outputIndex: 0, note: mkNote(100, pkSeed = 3)
        )

      let
        tx3 = mkTransferTx(
          [utxoAfter2.id], [mkNote(60, pkSeed = 4), mkNote(40, pkSeed = 5)]
        )
        r3 = l.prepareUpdate(
          id = mkId(0x03),
          parentId = mkId(0x02),
          slot = 3'u64,
          proof = mkProof(),
          txs = [ValidSignedMantleTx(tx3)],
        )
      check r3.isOk
      l.commitUpdate(r3.get.id, r3.get.state)

      check l.state(mkId(0x00)).isSome
      check l.state(mkId(0x01)).isSome
      check l.state(mkId(0x02)).isSome
      check l.state(mkId(0x03)).isSome
      check l.state(mkId(0x03)).get.latestUtxos.len == 2

      check not l.state(mkId(0x03)).get.latestUtxos.contains(input1.id)
      check not l.state(mkId(0x03)).get.latestUtxos.contains(utxoAfter1.id)
      check not l.state(mkId(0x03)).get.latestUtxos.contains(utxoAfter2.id)

suite "tryApplyTx — SDP":
  test "declare locks note; withdraw unlocks after finalization":
    let input = mkUtxo(value = 200, pkSeed = 1)
    var state = mkState([input])
    let declaration = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: mkProvider(1),
      lockedNoteId: input.id,
      zkId: input.note.zkPublicKey,
    )
    let declId = installTestDeclaration(state.sdp, declaration, epoch = 1)
    check declId in state.sdp.state.declarations

    let spendOp = TransferPayload(
      inputs: Inputs(noteIds: @[input.id]),
      outputs: Outputs(notes: @[mkNote(200, pkSeed = 2)]),
    )
    let locked = state.cryptarchiaLedger.applyTransferState(
      state.sdp.state.lockedNotes, state.mantleLedger.channelNotes, spendOp,
    )
    check locked.isErr
    check locked.error == LedgerError.LockedNote

    let withdraw = WithdrawMessage(
      declarationId: declId,
      lockedNoteId: input.id,
      nonce: 1,
    )
    installTestWithdraw(state.sdp, withdraw, epoch = 5)
    let stillLocked = state.cryptarchiaLedger.applyTransferState(
      state.sdp.state.lockedNotes, state.mantleLedger.channelNotes, spendOp,
    )
    check stillLocked.isErr

    state.sdp.state = finalizeWithdrawals(state.sdp.state, 7)
    let unlocked = state.cryptarchiaLedger.applyTransferState(
      state.sdp.state.lockedNotes, state.mantleLedger.channelNotes, spendOp,
    )
    check unlocked.isOk

  test "prepareUpdate commits registry state from parent":
    let input = mkUtxo(value = 200, pkSeed = 3)
    var parent = mkState([input])
    let declaration = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: mkProvider(3),
      lockedNoteId: input.id,
      zkId: input.note.zkPublicKey,
    )
    discard installTestDeclaration(parent.sdp, declaration, epoch = 1)
    let id0 = mkId(0x10)
    var l = initLedger(id0, parent, testLedgerConfig)
    let r = l.prepareUpdate(
      id = mkId(0x11),
      parentId = id0,
      slot = 1'u64,
      proof = mkProof(),
      txs = @[],
    )
    check r.isOk
    l.commitUpdate(r.get.id, r.get.state)
    check declarationId(declaration) in l.state(mkId(0x11)).get.sdp.state.declarations

const noTxs: seq[ValidSignedMantleTx] = @[]
  ## Empty block contents; a compile-time value stays gcsafe, a `let` would not.

suite "block rewards — per-block leader crediting":
  # At every stake these fixtures reach, the interpolation weight pins at
  # A_SCALE, so one block emits a leader share of 38.
  const emission = 38'u64

  test "an empty block credits the pool with the block emission":
    # `pending` is private; it surfaces in `leadersRewards` once the next
    # epoch rotation rolls it in.
    var s = mkState([mkUtxo()])
    s = s.tryApplyHeader(1'u64, mkProof(), testLedgerConfig).expect("header")
    s = s.tryApplyTxns(
      noTxs, slot = 1'u64, verifyPoq = acceptAllPoq).expect("txns")
    check s.cryptarchiaLedger.leader.leadersRewards == 0
    s = s.tryApplyHeader(100'u64, mkProof(), testLedgerConfig).expect("rotation")
    check s.cryptarchiaLedger.leader.leadersRewards == emission

  test "each applied block advances the block number":
    var s = mkState([mkUtxo()])
    check s.blockNumber == 0'u64
    s = s.tryApplyTxns(
      noTxs, slot = 1'u64, verifyPoq = acceptAllPoq).expect("block 1")
    s = s.tryApplyTxns(
      noTxs, slot = 2'u64, verifyPoq = acceptAllPoq).expect("block 2")
    check:
      s.blockNumber == 2'u64
      s.feeWindow.summedFees == u128(0)

  test "burned fees enter the window and tips top up the leader share":
    # No in-tree transfer fixture carries a surplus, so the fee split is
    # driven through the block-closing step directly.
    let
      s0 = mkState([mkUtxo()])
      s1 = s0.creditBlockRewards(
        totalFeeBurned = GasCost(700), totalFeeTip = GasCost(250)
      ).expect("credited")
    check:
      s1.blockNumber == 1'u64
      s1.feeWindow.summedFees == u128(700)
      s1.cryptarchiaLedger.leader.leadersRewards == 0
    let rolled = s1.tryApplyHeader(100'u64, mkProof(), testLedgerConfig)
      .expect("rotation")
    check rolled.cryptarchiaLedger.leader.leadersRewards == emission + 250

  test "a rotating block credits the epoch it opens, not the one it closes":
    var s = mkState([mkUtxo()])
    s = s.tryApplyHeader(1'u64, mkProof(), testLedgerConfig).expect("header")
    s = s.tryApplyTxns(
      noTxs, slot = 1'u64, verifyPoq = acceptAllPoq).expect("txns")
    # The rotation rolls epoch 0's pending pool; the rotating block's own
    # reward is credited afterwards, so it belongs to epoch 1.
    s = s.tryApplyHeader(100'u64, mkProof(), testLedgerConfig).expect("rotation")
    s = s.tryApplyTxns(
      noTxs, slot = 100'u64, verifyPoq = acceptAllPoq).expect("txns")
    check s.cryptarchiaLedger.leader.leadersRewards == emission
    s = s.tryApplyHeader(200'u64, mkProof(), testLedgerConfig).expect("rotation")
    check s.cryptarchiaLedger.leader.leadersRewards == 2 * emission

  test "each block accrues the blend share as epoch income":
    # The same fixtures emit a blend share of 57 (60% against leader's 38).
    var s = mkState([mkUtxo()])
    s = s.creditBlockRewards(GasCost(0), GasCost(0)).expect("credited")
    check s.sdp.blendRewards.epochIncome == 57
    s = s.creditBlockRewards(GasCost(0), GasCost(0)).expect("credited")
    check s.sdp.blendRewards.epochIncome == 114

  test "a rotation without blend providers mints nothing, resets income":
    var s = mkState([mkUtxo()])
    s = s.creditBlockRewards(GasCost(0), GasCost(0)).expect("credited")
    let utxosBefore = s.latestUtxos.len
    s = s.tryApplyHeader(100'u64, mkProof(), testLedgerConfig).expect("rotation")
    check s.latestUtxos.len == utxosBefore
    check s.sdp.blendRewards.target.isNone
    check s.sdp.blendRewards.epochIncome == 0

{.pop.}
