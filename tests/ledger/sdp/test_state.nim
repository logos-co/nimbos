# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  results,
  std/sets,
  unittest2,
  libp2p/multiaddress,
  ./test_helpers,
  ../../../logos_chain/core/mantle/primitives,
  ../../../logos_chain/ledger/sdp/state,
  ../../../logos_chain/zk/poseidon2/hasher

suite "ledger/sdp/state":
  test "DeclarationInfo fields are default-zero":
    var d: DeclarationInfo
    check d.nonce == 0'u64
    check d.service == ServiceType.bn
    check d.active.isNone
    check d.withdrawAt.isNone

  test "validateLocator accepts valid locator and rejects oversized ones":
    let good = MultiAddress.init("/ip4/127.0.0.1/tcp/30303").tryGet()
    check isValidLocator(good)

    check MultiAddress.init("not-a-multiaddr").isErr

    var longMaStr = "/ip4/127.0.0.1/tcp/30303"
    while MultiAddress.init(longMaStr).tryGet().data().buffer.len <= MaxLocatorMultiaddrBytes:
      longMaStr &= "/ip4/1.1.1.1"
    let tooLong = MultiAddress.init(longMaStr).tryGet()
    check not isValidLocator(tooLong)

  func seedNoteId(seed: byte): NoteId =
    var bytes: array[32, byte]
    bytes[0] = seed
    frFromBytesLE(bytes).get

  func seedDeclId(seed: byte): DeclarationId =
    var id: DeclarationId
    id[0] = seed
    id

  proc checkInvariants(state: SdpState) =
    check state.activeProviders.len == state.declarations.len
    check state.activeZkIds.len == state.declarations.len
    for declId, info in state.declarations.pairs:
      check (info.service, info.providerId) in state.activeProviders
      check (info.service, info.zkId) in state.activeZkIds
      check info.lockedNoteId in state.lockedNotes
      let declsInNote = state.lockedNotes.get(info.lockedNoteId).get()
      check declId in declsInNote

  test "stores declarations and locked notes":
    var state = SdpState.init()
    let declId = seedDeclId(1)
    let noteId = seedNoteId(2)

    check declId notin state.declarations
    check getDeclaration(state, declId).isNone

    var info: DeclarationInfo
    info.service = ServiceType.bn
    info.created = 10'u64
    state = insertDeclaration(state, declId, info)
    check declId in state.declarations
    check getDeclaration(state, declId).get().created == 10'u64

    state = addDeclarationToLockedNote(state, noteId, declId)
    check noteId in state.lockedNotes
    check getLockedNote(state, noteId).get().len == 1

    let otherDecl = seedDeclId(3)
    state = addDeclarationToLockedNote(state, noteId, otherDecl)
    check getLockedNote(state, noteId).get().len == 2

    state = removeDeclarationFromLockedNote(state, noteId, otherDecl)
    check noteId in state.lockedNotes
    state = removeDeclarationFromLockedNote(state, noteId, declId)
    check noteId notin state.lockedNotes

    state = removeDeclaration(state, declId)
    check declId notin state.declarations

  test "finalizeWithdrawals removes declarations and unlocks notes":
    var state = SdpState.init()
    let declId = seedDeclId(7)
    let noteId = seedNoteId(8)
    var info: DeclarationInfo
    info.service = ServiceType.bn
    info.lockedNoteId = noteId
    info.withdrawAt = Opt.some(5'u64)
    state = insertDeclaration(state, declId, info)
    state = addDeclarationToLockedNote(state, noteId, declId)

    state = finalizeWithdrawals(state, 6)
    check declId in state.declarations
    check noteId in state.lockedNotes

    state = finalizeWithdrawals(state, 7)
    check declId notin state.declarations
    check noteId notin state.lockedNotes

  test "hasProviderOrZkIdConflict uses secondary index maps":
    var state = SdpState.init()
    let declId = seedDeclId(10)
    var info: DeclarationInfo
    info.service = ServiceType.bn
    info.providerId = mkProvider(1)
    info.zkId = seedNoteId(9)

    check not hasProviderOrZkIdConflict(state, info.service, info.providerId, info.zkId)
    state = insertDeclaration(state, declId, info)
    check hasProviderOrZkIdConflict(state, info.service, info.providerId, info.zkId)

    # Provider and ZK ID remain conflict-protected until declaration is removed
    state = removeDeclaration(state, declId)
    check not hasProviderOrZkIdConflict(state, info.service, info.providerId, info.zkId)

  test "SdpState preserves invariants across declare, active, withdraw, and finalization":
    var seeded1 = seedDeclaration(pkSeed = 1, declareEpoch = 1)
    let seeded2 = seedDeclaration(pkSeed = 2, declareEpoch = 1)
    checkInvariants(seeded1.registry.state)

    # Apply second declaration into seeded1 registry
    let declareRes2 = applySdpDeclare(seeded1.registry, seeded2.declaration, 1)
    check declareRes2.isOk
    seeded1.registry = declareRes2.get()
    checkInvariants(seeded1.registry.state)

    # Execute active on decl 1
    let activeMsg1 = ActiveMessage(
      declarationId: seeded1.declId,
      nonce: 1,
    )
    let decl1 = seeded1.registry.state.declarations.get(seeded1.declId).get()
    seeded1.registry = applySdpActive(seeded1.registry, activeMsg1, decl1, 2)
    checkInvariants(seeded1.registry.state)

    # Execute withdraw on decl 1 at epoch 5
    let withdrawMsg1 = WithdrawMessage(
      declarationId: seeded1.declId,
      lockedNoteId: seeded1.declaration.lockedNoteId,
      nonce: 2,
    )
    let decl1Active = seeded1.registry.state.declarations.get(seeded1.declId).get()
    seeded1.registry = applySdpWithdraw(seeded1.registry, withdrawMsg1, decl1Active, 5)
    checkInvariants(seeded1.registry.state)

    # Epoch hook at epoch 6 (snapshot/finalization) — does not prune epoch 5 withdrawal yet
    seeded1.registry = onEpochStarted(seeded1.registry, 6)
    checkInvariants(seeded1.registry.state)
    check seeded1.declId in seeded1.registry.state.declarations

    # Epoch hook at epoch 7 — prunes epoch 5 withdrawal
    seeded1.registry = onEpochStarted(seeded1.registry, 7)
    checkInvariants(seeded1.registry.state)
    check seeded1.declId notin seeded1.registry.state.declarations

{.pop.}
