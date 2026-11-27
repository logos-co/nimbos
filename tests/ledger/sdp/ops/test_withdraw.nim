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
  results,
  ../test_helpers,
  ../../../zk/zksign_helpers

from ../../../core/mantle/test_helpers import mkRealZkPubKey, mkUtxoWithPk

suite "ledger/sdp/ops/withdraw":
  test "tryApplySdpWithdraw rejects unknown declaration":
    let seeded = seedDeclaration(pkSeed = 11, declareEpoch = 10)
    var unknown = WithdrawMessage(
      declarationId: seeded.declId,
      nonce: nonce(10, 1),
    )
    unknown.declarationId[0] = byte(99)
    check execWithdraw(seeded, unknown, 15).error == DeclarationNotFound

  test "tryApplySdpWithdraw rejects a second withdraw":
    var seeded = seedDeclaration(pkSeed = 12, declareEpoch = 10)
    let withdraw = WithdrawMessage(
      declarationId: seeded.declId,
      nonce: nonce(10, 1),
    )
    installTestWithdraw(seeded.registry, withdraw, withdrawAt = 15)
    var second = withdraw
    second.nonce = nonce(10, 2)
    check execWithdraw(seeded, second, 15).error == AlreadyWithdrawn

  test "tryApplySdpWithdraw rejects a nonce outside the lifecycle or sequence":
    # A packed u64 nonce comparison accepts nonce(11, 6) and fails this.
    var seeded = seedDeclaration(pkSeed = 14, declareEpoch = 10)
    let declaration = getDeclaration(seeded.registry.state, seeded.declId).get()
    seeded.registry = applySdpActive(
      seeded.registry,
      ActiveMessage(declarationId: seeded.declId, nonce: nonce(10, 5)),
      declaration, 11)
    for stale in [
        nonce(11, 6), nonce(9, high(uint32)), nonce(10, 5), nonce(10, 4)]:
      checkpoint("nonce " & $stale)
      let withdraw = WithdrawMessage(declarationId: seeded.declId, nonce: stale)
      check execWithdraw(seeded, withdraw, 16).error == InvalidNonce

  test "tryApplySdpWithdraw rejects an epoch too close to the limit":
    let
      seeded = seedDeclaration(pkSeed = 15, declareEpoch = 1)
      withdraw = WithdrawMessage(
        declarationId: seeded.declId,
        nonce: nonce(1, 1),
      )
    check execWithdraw(seeded, withdraw, high(EpochNumber) - 1).error ==
      InvalidEpoch
    # One epoch lower passes the gate and reaches the signature step.
    check execWithdraw(seeded, withdraw, high(EpochNumber) - 2).error in
      {VerifierNotInitialised, PermanentInvalidTxProof}

  test "tryApplySdpWithdraw schedules the withdrawal from the declaration's own note":
    # Fails if withdraw does not take the note from the declaration.
    # The fixture signs over [note pk, zk_id] = [mkRealZkPubKey(1), zero pk].
    check installZksignVk(zksignFixtureVk)
    let
      utxo = mkUtxoWithPk(mkRealZkPubKey(1), value = 200)
      store = UtxoStore.init().insert(utxo.id, utxo).store
      declaration = DeclarationMessage(
        serviceType: ServiceType.bn,
        locators: @[mkLocator(30303)],
        providerId: mkProvider(17),
        lockedNoteId: utxo.id,
        zkId: ZeroSecretKeyPublicKey,
      )
    var registry = testSdpRegistry()
    let
      declId = installTestDeclaration(registry, declaration, 3)
      applied = tryApplySdpWithdraw(
        registry,
        WithdrawMessage(declarationId: declId, nonce: nonce(3, 7)),
        loadProof(zksignFixtureProof),
        loadTxHash(zksignFixturePublic),
        store,
        4,
      ).expect("valid withdraw")
      info = getDeclaration(applied.state, declId).get()
    check:
      info.withdrawAt == Opt.some(6'u32)
      info.nonce == nonce(3, 7)
      getLockedNote(applied.state, utxo.id).isSome

{.pop.}
