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
  poseidon2/types,          # `==` for F
  ../../logos_chain/ledger/
    [balance, cryptarchia_state, locked_notes, types, utxo_store],
  ../../logos_chain/core/mantle/[primitives, operations, proofs, tx_hashing, utxo],
  ../../logos_chain/zk/zksign,
  ../zk/zksign_helpers,
  ../core/mantle/test_helpers

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  zksignFixtureDir = testsDir / "../fixtures/zksign"
  fixtureVk = zksignFixtureDir / "verification_key.json"
  fixtureProof = zksignFixtureDir / "proof.json"
  fixturePublic = zksignFixtureDir / "public.json"

suite "CryptarchiaState init":
  test "empty init has no utxos":
    let s = CryptarchiaState.init()
    check s.len == 0
    check s.isEmpty
    check s.root == UtxoStore.init().root

  test "init from empty UtxoStore equivalent to empty init":
    let
      a = CryptarchiaState.init()
      b = CryptarchiaState.init(UtxoStore.init())
    check a == b

  test "init from seed populates correctly":
    let
      u1 = mkUtxo(value = 50, pkSeed = 1)
      u2 = mkUtxo(value = 100, pkSeed = 2)
      u3 = mkUtxo(value = 150, pkSeed = 3)
      s = CryptarchiaState.init([u1, u2, u3])
    check s.len == 3
    check s.utxos.contains(u1.id)
    check s.utxos.contains(u2.id)
    check s.utxos.contains(u3.id)

  test "two empty states are equal":
    check CryptarchiaState.init() == CryptarchiaState.init()

suite "CryptarchiaState reads":
  test "root delegates to UtxoStore":
    let
      u = mkUtxo()
      s = CryptarchiaState.init([u])
    check s.root == s.utxos.root

  test "latestUtxos returns the inner store":
    let
      u = mkUtxo()
      s = CryptarchiaState.init([u])
    check s.latestUtxos == s.utxos

suite "tryApplyTransfer — error paths":
  setup:
    check installZksignVk(fixtureVk)

  test "missing input → InvalidNote (three shapes)":
    let
      seeded = mkUtxo(value = 100, pkSeed = 1)
      s0 = CryptarchiaState.init([seeded])

      wrongIdx = mkUtxo(value = 100, pkSeed = 1, outputIndex = 1)
      wrongHash = mkUtxo(value = 100, pkSeed = 1, opIdSeed = 9)
      wrongValue = mkUtxo(value = 99, pkSeed = 1)

    for missing in [wrongIdx, wrongHash, wrongValue]:
      let
        op = TransferPayload(
          inputs: Inputs(noteIds: @[missing.id]),
          outputs: Outputs(notes: @[mkNote(50, pkSeed = 2)]),
        )
        r = s0.tryApplyTransfer(
          LockedNotes.init(),
          op,
          sig = default(ZkSigProof),
          txHash = mkTxHash(),
        )
      check r.isErr
      check r.error == InvalidNote

  test "locked input → LockedNote":
    let
      input = mkUtxo(value = 100, pkSeed = 1)
      s0 = CryptarchiaState.init([input])
      locked = LockedNotes.init([input.id])
      op = TransferPayload(
        inputs: Inputs(noteIds: @[input.id]),
        outputs: Outputs(notes: @[mkNote(100, pkSeed = 2)]),
      )
      r = s0.tryApplyTransfer(
        locked,
        op,
        sig = default(ZkSigProof),
        txHash = mkTxHash(),
      )
    check r.isErr
    check r.error == LockedNote

  test "bad signature → InvalidProof":
    let
      input = mkUtxo(value = 100, pkSeed = 1)
      s0 = CryptarchiaState.init([input])
      op = TransferPayload(
        inputs: Inputs(noteIds: @[input.id]),
        outputs: Outputs(notes: @[mkNote(100, pkSeed = 2)]),
      )
      r = s0.tryApplyTransfer(
        LockedNotes.init(),
        op,
        sig = default(ZkSigProof),
        txHash = mkTxHash(),
      )
    check r.isErr
    check r.error == InvalidProof

  test "verify before VK install → VerifierNotInitialised":
    zksign.resetVkForTesting()
    let
      input = mkUtxo(value = 100, pkSeed = 1)
      s0 = CryptarchiaState.init([input])
      op = TransferPayload(
        inputs: Inputs(noteIds: @[input.id]),
        outputs: Outputs(notes: @[mkNote(100, pkSeed = 2)]),
      )
      r = s0.tryApplyTransfer(
        LockedNotes.init(),
        op,
        sig = default(ZkSigProof),
        txHash = mkTxHash(),
      )
    check r.isErr
    check r.error == VerifierNotInitialised

suite "tryApplyTransfer — happy paths (fixture-driven)":
  # All tests in this suite use the 1-key zksign fixture (`PK(SK=1)`-signed).
  # Inputs are constructed with `mkUtxoWithPk(mkRealZkPubKey(1), ...)` so the
  # collected pks vector matches what the prover signed; the fixture's msg +
  # proof get passed verbatim.
  var
    signerPk: ZkPublicKey
    sig: ZkSigProof
    txHash: ZkHash

  setup:
    check installZksignVk(fixtureVk)
    signerPk = mkRealZkPubKey(1)
    sig = loadProof(fixtureProof)
    txHash = loadTxHash(fixturePublic)

  test "1-in / 1-out same value":
    let
      input = mkUtxoWithPk(signerPk, value = 100)
      s0 = CryptarchiaState.init([input])
      op = TransferPayload(
        inputs: Inputs(noteIds: @[input.id]),
        outputs: Outputs(notes: @[mkNote(100, pkSeed = 2)]),
      )
      r = s0.tryApplyTransfer(LockedNotes.init(), op, sig, txHash)
    check r.isOk

    let (s1, balance) = r.get
    check balance == Balance.zero
    check s1.len == 1
    check not s1.utxos.contains(input.id)

  test "split (1 input, 3 outputs)":
    let
      input = mkUtxoWithPk(signerPk, value = 100)
      s0 = CryptarchiaState.init([input])
      op = TransferPayload(
        inputs: Inputs(noteIds: @[input.id]),
        outputs: Outputs(
          notes:
            @[mkNote(30, pkSeed = 2), mkNote(30, pkSeed = 3), mkNote(40, pkSeed = 4)]
        ),
      )
      r = s0.tryApplyTransfer(LockedNotes.init(), op, sig, txHash)
    check r.isOk

    let (s1, balance) = r.get
    check balance == Balance.zero
    check s1.len == 3
    check not s1.utxos.contains(input.id)

  test "zero-value output → ZeroValueNote":
    let
      input = mkUtxoWithPk(signerPk, value = 100)
      s0 = CryptarchiaState.init([input])
      op = TransferPayload(
        inputs: Inputs(noteIds: @[input.id]),
        outputs: Outputs(notes: @[mkNote(0, pkSeed = 2)]),
      )
      r = s0.tryApplyTransfer(LockedNotes.init(), op, sig, txHash)
    check r.isErr
    check r.error == ZeroValueNote

  test "no outputs → balance equals full input value":
    let
      input = mkUtxoWithPk(signerPk, value = 100)
      s0 = CryptarchiaState.init([input])
      op = TransferPayload(
        inputs: Inputs(noteIds: @[input.id]), outputs: Outputs(notes: @[])
      )
      r = s0.tryApplyTransfer(LockedNotes.init(), op, sig, txHash)
    check r.isOk

    let (s1, balance) = r.get
    check balance == i128(100)
    check s1.len == 0
    check not s1.utxos.contains(input.id)

  test "outputs exceed input → returns negative balance":
    let
      input = mkUtxoWithPk(signerPk, value = 1)
      s0 = CryptarchiaState.init([input])
      op = TransferPayload(
        inputs: Inputs(noteIds: @[input.id]),
        outputs: Outputs(notes: @[mkNote(1, pkSeed = 2), mkNote(1, pkSeed = 3)]),
      )
      r = s0.tryApplyTransfer(LockedNotes.init(), op, sig, txHash)
    check r.isOk

    let (s1, balance) = r.get
    check balance == i128(-1)
    check s1.len == 2

  test "unbalanced (input > output) returns positive balance":
    let
      input = mkUtxoWithPk(signerPk, value = 11000)
      s0 = CryptarchiaState.init([input])
      op = TransferPayload(
        inputs: Inputs(noteIds: @[input.id]),
        outputs:
          Outputs(notes: @[mkNote(4000, pkSeed = 2), mkNote(3000, pkSeed = 3)]),
      )
      r = s0.tryApplyTransfer(LockedNotes.init(), op, sig, txHash)
    check r.isOk

    let (s1, balance) = r.get
    check balance == i128(11000 - 4000 - 3000) # = 4000 surplus
    check s1.len == 2

  test "parent state unchanged when child applies a transfer":
    let
      input = mkUtxoWithPk(signerPk, value = 100)
      s0 = CryptarchiaState.init([input])
      preLen = s0.len
      preRoot = s0.root
      op = TransferPayload(
        inputs: Inputs(noteIds: @[input.id]),
        outputs: Outputs(notes: @[mkNote(100, pkSeed = 2)]),
      )
    discard s0.tryApplyTransfer(LockedNotes.init(), op, sig, txHash)

    check s0.len == preLen
    check s0.root == preRoot
    check s0.utxos.contains(input.id)

suite "applyTransferState — multi-input":
  test "multi-input combine (2 inputs, 1 output)":
    let
      a = mkUtxo(value = 60, pkSeed = 1)
      b = mkUtxo(value = 40, pkSeed = 1, opIdSeed = 1)
      s0 = CryptarchiaState.init([a, b])
      op = TransferPayload(
        inputs: Inputs(noteIds: @[a.id, b.id]),
        outputs: Outputs(notes: @[mkNote(100, pkSeed = 2)]),
      )
      r = s0.applyTransferState(LockedNotes.init(), op)
    check r.isOk

    let (s1, balance, pks) = r.get
    check balance == Balance.zero
    check s1.len == 1
    check not s1.utxos.contains(a.id)
    check not s1.utxos.contains(b.id)
    check pks.len == 2

suite "applyTransferState — chain":
  test "chain of txs: tx2 spends outputs created by tx1":
    let
      input = mkUtxo(value = 100, pkSeed = 1)
      s0 = CryptarchiaState.init([input])
      tx1 = TransferPayload(
        inputs: Inputs(noteIds: @[input.id]),
        outputs: Outputs(notes: @[mkNote(60, pkSeed = 2), mkNote(40, pkSeed = 3)]),
      )
      r1 = s0.applyTransferState(LockedNotes.init(), tx1)
    check r1.isOk

    let
      s1 = r1.get.state
      tx1OpId = opId(tx1)
      outUtxo0 =
        Utxo(opId: tx1OpId, outputIndex: 0, note: mkNote(60, pkSeed = 2))
      outUtxo1 =
        Utxo(opId: tx1OpId, outputIndex: 1, note: mkNote(40, pkSeed = 3))

    check s1.utxos.contains(outUtxo0.id)
    check s1.utxos.contains(outUtxo1.id)

    let
      tx2 = TransferPayload(
        inputs: Inputs(noteIds: @[outUtxo0.id, outUtxo1.id]),
        outputs: Outputs(notes: @[mkNote(100, pkSeed = 4)]),
      )
      r2 = s1.applyTransferState(LockedNotes.init(), tx2)
    check r2.isOk

    let (s2, balance2, pks2) = r2.get
    check balance2 == Balance.zero
    check s2.len == 1
    check not s2.utxos.contains(outUtxo0.id)
    check not s2.utxos.contains(outUtxo1.id)
    check pks2.len == 2

{.pop.}
