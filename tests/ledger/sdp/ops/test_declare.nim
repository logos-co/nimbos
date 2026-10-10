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
  ../test_helpers

suite "ledger/sdp/ops/declare":
  test "tryApplySdpDeclare rejects invalid proof":
    let utxo = mkUtxo(value = 200, pkSeed = 1)
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
      registry = testSdpRegistry()
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
    let
      registry = testSdpRegistry()
      registryCopy = registry
    check execDeclare(registryCopy, declaration, store, 1).isErr

    var missingNote = declaration
    missingNote.lockedNoteId = frFromBytesLE([byte(99)]).get
    check execDeclare(registry, missingNote, store, 1).isErr

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
      registry = testSdpRegistry()
      declareResult = execDeclare(registry, declaration, store, 1, channelNotes)
    check:
      declareResult.isErr
      declareResult.error == ChannelNoteSpend

  test "tryApplySdpDeclare stores declaration":
    let
      seeded = seedDeclaration(pkSeed = 4, declareEpoch = 10)
      info = getDeclaration(seeded.registry.state, seeded.declId).get()
    check:
      info.created == 10'u64
      info.active.isNone
      info.withdrawAt.isNone
      info.nonce == 0'u64
      getLockedNote(seeded.registry.state, seeded.declaration.lockedNoteId).isSome

  test "tryApplySdpDeclare rejects duplicate providerId or zkId for the same service":
    let
      seeded = seedDeclaration(pkSeed = 4, declareEpoch = 10)
      utxo = mkUtxo(value = 200, pkSeed = 8)
      store = seeded.store.insert(utxo.id, utxo).store
      declaration2 = DeclarationMessage(
        serviceType: ServiceType.bn,
        locators: @[mkLocator(30304)],
        providerId: seeded.declaration.providerId,
        lockedNoteId: utxo.id,
        zkId: utxo.note.zkPublicKey,
      )
      declareResult = execDeclare(seeded.registry, declaration2, store, 1)
    check:
      declareResult.isErr
      declareResult.error == DuplicateProviderOrZkId

{.pop.}
