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
  ../../../logos_chain/core/mantle/primitives,
  ../../../logos_chain/core/sdp/state,
  ../../../logos_chain/zk/poseidon2/hasher

suite "core/sdp/state":
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

{.pop.}
