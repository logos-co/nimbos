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
  libp2p/[crypto/ed25519/ed25519, multiaddress],
  ../../../logos_chain/core/crypto/hashing,
  ../../../logos_chain/core/mantle/[operations, tx_hashing],
  ../../../logos_chain/zk/poseidon2/hasher

suite "core/mantle/operations — declarationId":
  proc mkProvider(seed: byte): ProviderId =
    var bytes: array[EdPublicKeySize, byte]
    bytes[0] = seed
    var key: ProviderId
    doAssert key.init(bytes)
    key

  proc mkLocator(port: int): Locator =
    MultiAddress.init("/ip4/127.0.0.1/tcp/" & $port).get()

  func seedZkId(seed: byte): ZkId =
    var bytes: array[32, byte]
    bytes[0] = seed
    frFromBytesLE(bytes).get

  func seedNoteId(seed: byte): NoteId =
    var bytes: array[32, byte]
    bytes[0] = seed
    frFromBytesLE(bytes).get

  test "declarationId is deterministic and excludes locked_note_id":
    let provider = mkProvider(1)
    let zkId = seedZkId(2)
    let locators = @[mkLocator(30303)]
    let base = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: locators,
      providerId: provider,
      zkId: zkId,
      lockedNoteId: seedNoteId(1),
    )
    var otherNote = base
    otherNote.lockedNoteId = seedNoteId(9)

    let idA = declarationId(base)
    let idB = declarationId(base)
    let idC = declarationId(otherNote)
    check idA == idB
    check idA == idC

  test "declarationId changes when identity fields change":
    let provider = mkProvider(1)
    let zkId = seedZkId(2)
    let locators = @[mkLocator(30303)]
    let base = declarationId(DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: locators,
      providerId: provider,
      zkId: zkId,
      lockedNoteId: default(NoteId),
    ))
    check base != declarationId(DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: locators,
      providerId: mkProvider(2),
      zkId: zkId,
      lockedNoteId: default(NoteId),
    ))
    check base != declarationId(DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: locators,
      providerId: provider,
      zkId: seedZkId(3),
      lockedNoteId: default(NoteId),
    ))
    check base != declarationId(DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[mkLocator(30304)],
      providerId: provider,
      zkId: zkId,
      lockedNoteId: default(NoteId),
    ))

  test "declarationId matches blake2b over identity preimage encoding":
    let provider = mkProvider(7)
    let zkId = seedZkId(4)
    let locators = @[mkLocator(30303), mkLocator(30304)]
    let decl = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: locators,
      providerId: provider,
      zkId: zkId,
      lockedNoteId: default(NoteId),
    )
    var preimage = @[encodeServiceType(decl.serviceType)]
    preimage.add(encodeProviderId(decl.providerId))
    preimage.add(encodeZkId(decl.zkId))
    preimage.add(encodeLocators(decl.locators))
    check declarationId(decl) == blake2b256Hash(preimage)

  test "declarationId is independent of full mantle SDPDeclare wire bytes":
    let provider = mkProvider(1)
    let zkId = seedZkId(2)
    let declare = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: provider,
      zkId: zkId,
      lockedNoteId: default(NoteId),
    )
    check declarationId(declare) != blake2b256Hash(encodeSdpDeclare(declare))
    check opId(declare) != declarationId(declare)

{.pop.}
