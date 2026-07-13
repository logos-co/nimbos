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

suite "core/sdp/ops/declare":
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
      locators: @[],
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
      locators: @[],
      providerId: mkProvider(1),
      lockedNoteId: utxo.id,
      zkId: utxo.note.zkPublicKey,
    )
    var registry = testSdpRegistry()
    check execDeclare(registry, declaration, store, 1).isErr

    var missingNote = declaration
    missingNote.lockedNoteId = frFromBytesLE([byte(99)]).get
    check execDeclare(registry, missingNote, store, 1).isErr

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

  test "tryApplySdpDeclare stores declaration":
    let seeded = seedDeclaration(pkSeed = 4, declareEpoch = 10)
    let info = getDeclaration(seeded.registry.state, seeded.declId).get()
    check info.created == 10'u64
    check info.active.isNone
    check info.withdrawAt.isNone
    check info.nonce == 0'u64
    check getLockedNote(seeded.registry.state, seeded.declaration.lockedNoteId).isSome

{.pop.}
