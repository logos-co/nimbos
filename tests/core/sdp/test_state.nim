# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[sets, tables],
  unittest2,
  libp2p/multiaddress,
  ../../../logos_chain/core/mantle/primitives,
  ../../../logos_chain/core/sdp/state,
  ../../../logos_chain/zk/poseidon2/hasher

suite "core/sdp/state":
  test "LockedNote starts with empty declaration set":
    var ln: LockedNote
    check len(ln.declarations) == 0
    check ln.lockedUntil == 0'u64

  test "DeclarationInfo fields are default-zero":
    var d: DeclarationInfo
    check d.nonce == 0'u64
    check d.service == ServiceType.bn

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

    state = addDeclarationToLockedNote(state, noteId, declId, 100'u64)
    check noteId in state.lockedNotes
    let locked = getLockedNote(state, noteId).get()
    check locked.declarations.len == 1
    check locked.lockedUntil == 100'u64

    state = addDeclarationToLockedNote(state, noteId, declId, 50'u64)
    check getLockedNote(state, noteId).get().lockedUntil == 100'u64

    let otherDecl = seedDeclId(3)
    state = addDeclarationToLockedNote(state, noteId, otherDecl, 200'u64)
    check getLockedNote(state, noteId).get().lockedUntil == 200'u64

    state = removeDeclarationFromLockedNote(state, noteId, otherDecl)
    check noteId in state.lockedNotes
    state = removeDeclarationFromLockedNote(state, noteId, declId)
    check noteId notin state.lockedNotes

    state = removeDeclaration(state, declId)
    check declId notin state.declarations

  const gcParams = ServiceParameters(
    sessionLength: 10, lockPeriod: 1,
    inactivityPeriod: 1, retentionPeriod: 1, timestamp: 0,
  )

  test "isDeclarationGarbage applies retention and inactivity rules":
    var withdrawn: DeclarationInfo
    withdrawn.service = ServiceType.bn
    withdrawn.active = 50'u64
    withdrawn.withdrawn = 50'u64
    check not isDeclarationGarbage(withdrawn, gcParams, 60)
    check isDeclarationGarbage(withdrawn, gcParams, 61)

    var inactive: DeclarationInfo
    inactive.service = ServiceType.bn
    inactive.active = 10'u64
    inactive.withdrawn = 0'u64
    check not isDeclarationGarbage(inactive, gcParams, 30)
    check isDeclarationGarbage(inactive, gcParams, 31)

    var recent: DeclarationInfo
    recent.service = ServiceType.bn
    recent.active = 25'u64
    recent.withdrawn = 0'u64
    check not isDeclarationGarbage(recent, gcParams, 45)
    check isDeclarationGarbage(recent, gcParams, 46)

  test "collectGarbage removes expired declarations and cleans locked notes":
    var state = SdpState.init()
    var parameters = initTable[ServiceType, ServiceParameters]()
    parameters[ServiceType.bn] = gcParams

    let declId = seedDeclId(7)
    let noteId = seedNoteId(8)
    var info: DeclarationInfo
    info.service = ServiceType.bn
    info.lockedNoteId = noteId
    info.active = 10'u64
    info.withdrawn = 0'u64
    state = insertDeclaration(state, declId, info)
    state = addDeclarationToLockedNote(state, noteId, declId, 100'u64)

    state = collectGarbage(state, parameters, 30)
    check declId in state.declarations
    check noteId in state.lockedNotes

    state = collectGarbage(state, parameters, 31)
    check declId notin state.declarations
    check noteId notin state.lockedNotes

{.pop.}
