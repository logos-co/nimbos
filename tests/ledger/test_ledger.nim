# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[os, strutils],
  unittest2,
  results,
  stew/io2,
  ../../logos_chain/ledger/
    [balance, cryptarchia_state, ledger, locked_notes, types],
  ../../logos_chain/core/mantle/[primitives, operations, proofs, tx_types, utxo],
  ../../logos_chain/core/types,
  ../../logos_chain/zk/pol,
  ../zk/[snarkjs_helpers, zksign_helpers],
  ../core/mantle/test_helpers

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  fixtureVk = testsDir / "../fixtures/pol/verification_key.json"
  zksignFixtureDir = testsDir / "../fixtures/zksign"
  zksignFixtureVk = zksignFixtureDir / "verification_key.json"
  transferProofPath = zksignFixtureDir / "proof.json"

suite "LedgerState constructors and reads":
  test "fromUtxos with empty seq → empty state":
    let s = LedgerState.fromUtxos(@[])
    check s.latestUtxos.len == 0

  test "fromUtxos with N utxos → state populated":
    let
      u1 = mkUtxo(value = 50, pkSeed = 1)
      u2 = mkUtxo(value = 100, pkSeed = 2)
      s = LedgerState.fromUtxos([u1, u2])
    check s.latestUtxos.len == 2
    check s.latestUtxos.contains(u1.id)
    check s.latestUtxos.contains(u2.id)

suite "tryApplyHeader":
  test "genesis-sentinel proof returns state unchanged":
    let
      u = mkUtxo()
      s0 = LedgerState.fromUtxos([u])
      r = s0.tryApplyHeader(slot = 1'u64, proof = mkProof())
    check r.isOk
    check r.get.latestUtxos == s0.latestUtxos

  test "returns VerifierNotInitialised when VK singleton missing":
    pol.resetVkForTesting()
    let s0 = LedgerState.fromUtxos([mkUtxo()])
    var bad = mkProof()
    bad.proof[0] = 0x01  # break the genesis sentinel so verify is invoked
    let r = s0.tryApplyHeader(slot = 1'u64, proof = bad)
    check r.error == VerifierNotInitialised

  test "returns InvalidProof when verifier rejects":
    pol.resetVkForTesting()
    let vkText = readAllChars(fixtureVk).valueOr:
      check false
      return
    let vk = parseVk(vkText).valueOr:
      check false
      return
    check pol.initVk(vk).isOk

    let s0 = LedgerState.fromUtxos([mkUtxo()])
    var bad = mkProof()
    bad.proof[0] = 0x01  # bit-pattern can't be a valid compressed G1 point
    let r = s0.tryApplyHeader(slot = 1'u64, proof = bad)
    check r.error == InvalidProof

suite "tryApplyTx — structural error paths":
  # No verify exercised — all errors fire before any tryApplyTransfer call.
  test "ops/proofs count mismatch → InvalidProof":
    let
      input = mkUtxo(value = 100, pkSeed = 1)
      s0 = LedgerState.fromUtxos([input])
      tx = SignedMantleTx(
        tx: MantleTx(
          ops:
            @[
              createTransferOp(
                TransferPayload(
                  inputs: Inputs(noteIds: @[input.id]),
                  outputs: Outputs(notes: @[mkNote(100, pkSeed = 2)]),
                )
              )
            ],
        ),
        opProofs: @[],
      ) # zero proofs vs one op
      r = s0.tryApplyTx(tx, LockedNotes.init())
    check r.isErr
    check r.error == InvalidProof

  test "non-Transfer op → UnsupportedOp":
    let
      s0 = LedgerState.fromUtxos(@[])
      op = createChannelInscribeOp(
        ChannelInscribePayload(
          channelId: default(ChannelId),
          inscription: @[],
          parent: default(Parent),
          signer: default(Signer),
        )
      )
      tx = SignedMantleTx(
        tx: MantleTx(ops: @[op]),
        opProofs:
          @[
            OpProof(kind: opfChannelInscribe, ed25519SigProof: default(Ed25519SigProof))
          ],
      )
      r = s0.tryApplyTx(tx, LockedNotes.init())
    check r.isErr
    check r.error == UnsupportedOp

  test "Transfer op with wrong proof kind → InvalidProof":
    let
      input = mkUtxo(value = 100, pkSeed = 1)
      s0 = LedgerState.fromUtxos([input])
      tx = SignedMantleTx(
        tx: MantleTx(
          ops:
            @[
              createTransferOp(
                TransferPayload(
                  inputs: Inputs(noteIds: @[input.id]),
                  outputs: Outputs(notes: @[mkNote(100, pkSeed = 2)]),
                )
              )
            ],
        ),
        opProofs:
          @[
            OpProof( # Ed25519 instead of ZkSig
              kind: opfChannelInscribe, ed25519SigProof: default(Ed25519SigProof)
            )
          ],
      )
      r = s0.tryApplyTx(tx, LockedNotes.init())
    check r.isErr
    check r.error == InvalidProof

suite "Ledger[Id] map ops":
  test "init seeds one (id, state); state(id) returns Some":
    let
      seed = LedgerState.fromUtxos(@[mkUtxo()])
      id = mkId(0x01)
      l = Ledger[TestId].init(id, seed)
    check l.state(id).isSome
    check l.state(mkId(0x02)).isNone

  test "commitUpdate overwrites":
    var l = Ledger[TestId].init(mkId(0x01), LedgerState.fromUtxos(@[]))
    let
      id2 = mkId(0x02)
      st2 = LedgerState.fromUtxos(@[mkUtxo(value = 7, pkSeed = 7)])
    l.commitUpdate(id2, st2)
    check l.state(id2).isSome
    check l.state(id2).get.latestUtxos.len == 1

  test "pruneStateAt removes existing, returns true; missing returns false":
    var l = Ledger[TestId].init(mkId(0x01), LedgerState.fromUtxos(@[]))
    check l.pruneStateAt(mkId(0x01)) == true
    check l.state(mkId(0x01)).isNone
    check l.pruneStateAt(mkId(0x99)) == false

suite "prepareUpdate — no-verify paths":
  test "parent missing → ParentNotFound":
    let
      l = Ledger[TestId].init(mkId(0x01), LedgerState.fromUtxos(@[]))
      r = l.prepareUpdate(
        id = mkId(0x02),
        parentId = mkId(0xff),
        slot = 1'u64,
        proof = mkProof(),
        txs = @[],
        lockedNotes = LockedNotes.init(),
      )
    check r.isErr
    check r.error == ParentNotFound

  test "empty tx list → state unchanged, no commit":
    let
      parent = LedgerState.fromUtxos(@[mkUtxo()])
      id0 = mkId(0x01)
      l = Ledger[TestId].init(id0, parent)
      id1 = mkId(0x02)
      r = l.prepareUpdate(
        id = id1,
        parentId = id0,
        slot = 1'u64,
        proof = mkProof(),
        txs = @[],
        lockedNotes = LockedNotes.init(),
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
      s0 = LedgerState.fromUtxos([input])
      outputNote = Note(value: 100, zkPublicKey: default(ZkPublicKey))
      tx = SignedMantleTx(
        tx: MantleTx(
          ops:
            @[
              createTransferOp(
                TransferPayload(
                  inputs: Inputs(noteIds: @[input.id]),
                  outputs: Outputs(notes: @[outputNote]),
                )
              )
            ],
        ),
        opProofs: @[
          OpProof(kind: opfTransfer, transferProof: loadProof(transferProofPath)),
        ],
      )
      r = s0.tryApplyTx(tx, LockedNotes.init())
    check r.isOk

    let res = r.get
    check res.balance == Balance.zero
    check res.state.latestUtxos.len == 1
    check not res.state.latestUtxos.contains(input.id)

# Suites below need a valid `OpProof` per transfer op — i.e. a zksign proof
# generated for that op's input pks + tx hash. nimbos has no Nim-side prover
# yet (only the verifier); re-enable these tests once a prover lands.
when false:
  suite "tryApplyTx — multi-op":
    test "two balanced Transfer ops → balance == 0, both applied":
      let
        in1 = mkUtxo(value = 100, pkSeed = 1)
        in2 = mkUtxo(value = 50, pkSeed = 2)
        s0 = LedgerState.fromUtxos([in1, in2])
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
            MantleTx(ops: @[op1, op2], permanentStorageGasPrice: 0, executionGasPrice: 0),
          opProofs:
            @[
              OpProof(kind: opfTransfer, transferProof: default(ZkSigProof)),
              OpProof(kind: opfTransfer, transferProof: default(ZkSigProof)),
            ],
        )
        r = s0.tryApplyTx(tx, LockedNotes.init())
      check r.isOk
      let res = r.get
      check res.balance == Balance.zero
      check res.state.latestUtxos.len == 2
      check not res.state.latestUtxos.contains(in1.id)
      check not res.state.latestUtxos.contains(in2.id)

    test "two ops, second has wrong proof kind → InvalidProof":
      let
        in1 = mkUtxo(value = 100, pkSeed = 1)
        in2 = mkUtxo(value = 50, pkSeed = 2)
        s0 = LedgerState.fromUtxos([in1, in2])
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
            MantleTx(ops: @[op1, op2], permanentStorageGasPrice: 0, executionGasPrice: 0),
          opProofs:
            @[
              OpProof(kind: opfTransfer, transferProof: default(ZkSigProof)),
              OpProof(kind: opfChannelInscribe, ed25519SigProof: default(Ed25519SigProof)),
            ],
        )
        r = s0.tryApplyTx(tx, LockedNotes.init())
      check r.isErr
      check r.error == InvalidProof

  suite "tryApplyTxns":
    test "balanced tx → state advances":
      let
        input = mkUtxo(value = 100, pkSeed = 1)
        s0 = LedgerState.fromUtxos([input])
        tx = mkTransferTx([input.id], [mkNote(100, pkSeed = 2)])
        r = s0.tryApplyTxns([tx], LockedNotes.init())
      check r.isOk
      check r.get.latestUtxos.len == 1

    test "underspending (output > input) → UnbalancedTransaction":
      let
        input = mkUtxo(value = 100, pkSeed = 1)
        s0 = LedgerState.fromUtxos([input])
        tx = mkTransferTx([input.id], [mkNote(60, pkSeed = 2), mkNote(50, pkSeed = 3)])
          # sum 110 > input 100
        r = s0.tryApplyTxns([tx], LockedNotes.init())
      check r.isErr
      check r.error == InsufficientBalance

    test "overspending (input > output) → UnbalancedTransaction":
      let
        input = mkUtxo(value = 100, pkSeed = 1)
        s0 = LedgerState.fromUtxos([input])
        tx = mkTransferTx([input.id], [mkNote(50, pkSeed = 2)]) # output 50 < input 100
        r = s0.tryApplyTxns([tx], LockedNotes.init())
      check r.isErr
      check r.error == UnbalancedTransaction

  suite "prepareUpdate — verify paths":
    test "happy path with one transfer + commit":
      var l = Ledger[TestId].init(
        mkId(0x01), LedgerState.fromUtxos([mkUtxo(value = 100, pkSeed = 1)])
      )
      let
        input = mkUtxo(value = 100, pkSeed = 1)
        tx = mkTransferTx([input.id], [mkNote(100, pkSeed = 2)])
        r = l.prepareUpdate(
          id = mkId(0x02),
          parentId = mkId(0x01),
          slot = 1'u64,
          proof = mkProof(),
          txs = @[tx],
          lockedNotes = LockedNotes.init(),
        )
      check r.isOk
      let prepared = r.get
      l.commitUpdate(prepared.id, prepared.state)
      check l.state(mkId(0x02)).isSome
      check l.state(mkId(0x02)).get.latestUtxos.len == 1
      check not l.state(mkId(0x02)).get.latestUtxos.contains(input.id)

    test "unbalanced tx → UnbalancedTransaction":
      let
        input = mkUtxo(value = 100, pkSeed = 1)
        l = Ledger[TestId].init(mkId(0x01), LedgerState.fromUtxos([input]))
        tx = mkTransferTx([input.id], [mkNote(50, pkSeed = 2)]) # 100 in, 50 out
        r = l.prepareUpdate(
          id = mkId(0x02),
          parentId = mkId(0x01),
          slot = 1'u64,
          proof = mkProof(),
          txs = @[tx],
          lockedNotes = LockedNotes.init(),
        )
      check r.isErr
      check r.error == UnbalancedTransaction

    test "multi-block IBD: 3 prepare+commit cycles":
      # Walks the same prepare→commit sequence the chain module will eventually
      # drive. Each block consumes the prior block's output as its input.
      var l = Ledger[TestId].init(
        mkId(0x00), LedgerState.fromUtxos([mkUtxo(value = 100, pkSeed = 1)])
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
          txs = @[tx1],
          lockedNotes = LockedNotes.init(),
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
          txs = @[tx2],
          lockedNotes = LockedNotes.init(),
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
          txs = @[tx3],
          lockedNotes = LockedNotes.init(),
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

{.pop.}
