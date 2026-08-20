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
  ../test_utxo_helpers

suite "ledger/sdp/ops/declare":
  test "tryApplySdpDeclare rejects invalid proof":
    let utxo = mkUtxo(value = 200, pkSeed = 1)
    var store = UtxoStore.init()
    store = store.insert(utxo.id, utxo).store
    let declaration = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[mkLocator(30303)],
      providerId: mkProvider(1),
      lockedNoteId: utxo.id,
      zkId: utxo.note.zkPublicKey,
    )
    var registry = testSdpRegistry()
    check execDeclare(registry, declaration, store, 1).isErr

  test "tryApplySdpDeclare rejects duplicate declaration_id":
    let utxo = mkUtxo(value = 200, pkSeed = 2)
    var store = UtxoStore.init()
    store = store.insert(utxo.id, utxo).store
    let declaration = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[mkLocator(30303)],
      providerId: mkProvider(1),
      lockedNoteId: utxo.id,
      zkId: utxo.note.zkPublicKey,
    )
    var registry = testSdpRegistry()
    discard installTestDeclaration(registry, declaration, 1)
    check execDeclare(registry, declaration, store, 2).isErr

  template checkSecondDeclareRejected(
      providerA, providerB: ProviderId,
      zkA, zkB: ZkPublicKey,
      expected: LedgerError,
  ) =
    ## Installs a declaration with `providerA`/`zkA`, then declares
    ## `providerB`/`zkB` on a fresh note and expects `expected`.
    let
      utxoA = mkUtxo(value = 200, pkSeed = 20)
      utxoB = mkUtxo(value = 200, pkSeed = 21)
    var store = UtxoStore.init()
    store = store.insert(utxoA.id, utxoA).store
    store = store.insert(utxoB.id, utxoB).store
    let
      declarationA = DeclarationMessage(
        serviceType: ServiceType.bn,
        locators: @[mkLocator(30401)],
        providerId: providerA,
        lockedNoteId: utxoA.id,
        zkId: zkA,
      )
      declarationB = DeclarationMessage(
        serviceType: ServiceType.bn,
        locators: @[mkLocator(30402)],
        providerId: providerB,
        lockedNoteId: utxoB.id,
        zkId: zkB,
      )
    var registry = testSdpRegistry()
    discard installTestDeclaration(registry, declarationA, 1)
    let declareResult = execDeclare(registry, declarationB, store, 2)
    check declareResult.isErr
    check declareResult.error == expected

  test "tryApplySdpDeclare rejects a provider_id already declared in the service":
    checkSecondDeclareRejected(
      mkProvider(10), mkProvider(10), mkZkPubKey(30), mkZkPubKey(31),
      DuplicateProviderId)

  test "tryApplySdpDeclare rejects a zk_id already declared in the service":
    checkSecondDeclareRejected(
      mkProvider(11), mkProvider(12), mkZkPubKey(30), mkZkPubKey(30),
      DuplicateZkId)

  test "tryApplySdpDeclare reports provider_id when both identifiers repeat":
    checkSecondDeclareRejected(
      mkProvider(13), mkProvider(13), mkZkPubKey(31), mkZkPubKey(31),
      DuplicateProviderId)

  test "tryApplySdpDeclare allows identifier reuse after withdrawal removal":
    var seeded = seedDeclaration(pkSeed = 26, declareEpoch = 1)
    installTestWithdraw(
      seeded.registry,
      WithdrawMessage(
        declarationId: seeded.declId,
        nonce: 1,
        lockedNoteId: seeded.declaration.lockedNoteId,
      ),
      2)
    seeded.registry.state = finalizeWithdrawals(seeded.registry.state, 4)
    # Uniqueness passes once the record is removed; the default test proof
    # then fails, so InvalidProof shows the scan no longer rejects the ids.
    let declareResult = execDeclare(
      seeded.registry, seeded.declaration, seeded.store, 4)
    check declareResult.isErr
    check declareResult.error == InvalidProof

  test "tryApplySdpDeclare rejects missing locked note and insufficient stake":
    let utxo = mkUtxo(value = 50, pkSeed = 3)
    var store = UtxoStore.init()
    store = store.insert(utxo.id, utxo).store
    let declaration = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[mkLocator(30303)],
      providerId: mkProvider(1),
      lockedNoteId: utxo.id,
      zkId: utxo.note.zkPublicKey,
    )
    var registry = testSdpRegistry()
    var registryCopy = registry
    check execDeclare(registryCopy, declaration, store, 1).isErr

    var missingNote = declaration
    missingNote.lockedNoteId = frFromBytesLE([byte(99)]).get
    check execDeclare(registry, missingNote, store, 1).isErr

  test "tryApplySdpDeclare rejects empty locators":
    let utxo = mkUtxo(value = 200, pkSeed = 6)
    var store = UtxoStore.init()
    store = store.insert(utxo.id, utxo).store
    let declaration = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: mkProvider(1),
      lockedNoteId: utxo.id,
      zkId: utxo.note.zkPublicKey,
    )
    var registry = testSdpRegistry()
    let declareResult = execDeclare(registry, declaration, store, 1)
    check declareResult.isErr
    check declareResult.error == EmptyLocators

  test "tryApplySdpDeclare rejects too many locators":
    let utxo = mkUtxo(value = 200, pkSeed = 5)
    var store = UtxoStore.init()
    store = store.insert(utxo.id, utxo).store
    var locators = newSeq[Locator](MaxSdpLocators + 1)
    for i in 0 ..< locators.len:
      locators[i] = mkLocator(30000 + i)
    let declaration = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: locators,
      providerId: mkProvider(1),
      lockedNoteId: utxo.id,
      zkId: utxo.note.zkPublicKey,
    )
    var registry = testSdpRegistry()
    let declareResult = execDeclare(registry, declaration, store, 1)
    check declareResult.isErr
    check declareResult.error == TooManyLocators

  test "tryApplySdpDeclare rejects a channel note as collateral":
    let utxo = mkUtxo(value = 200, pkSeed = 7)
    var store = UtxoStore.init()
    store = store.insert(utxo.id, utxo).store
    let
      declaration = DeclarationMessage(
        serviceType: ServiceType.bn,
        locators: @[mkLocator(30303)],
        providerId: mkProvider(1),
        lockedNoteId: utxo.id,
        zkId: utxo.note.zkPublicKey,
      )
      channelNotes = ChannelNotes.init()
        .registerChannelNote(utxo.id, mkChannelId(1)).expect("fresh note")
    var registry = testSdpRegistry()
    let declareResult = execDeclare(registry, declaration, store, 1, channelNotes)
    check declareResult.isErr
    check declareResult.error == ChannelNoteSpend

  test "tryApplySdpDeclare stores declaration":
    let seeded = seedDeclaration(pkSeed = 4, declareEpoch = 10)
    let info = getDeclaration(seeded.registry.state, seeded.declId).get()
    check info.created == 10'u64
    check info.active.isNone
    check info.withdrawAt.isNone
    check info.nonce == 0'u64
    check getLockedNote(seeded.registry.state, seeded.declaration.lockedNoteId).isSome

{.pop.}
