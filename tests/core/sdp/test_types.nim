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
  ../../../logos_chain/core/crypto/hashing,
  ../../../logos_chain/core/mantle/[operations, tx_hashing],
  ../../../logos_chain/core/sdp/types,
  ../../../logos_chain/zk/poseidon2/hasher,
  ./test_helpers

suite "core/sdp/types":
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

  test "declarationId hashes UTF-8 BN service tag, not wire ServiceType byte":
    check encodeServiceTypeAsString(ServiceType.bn) == @[66'u8, 78'u8]
    let provider = mkProvider(7)
    let zkId = seedZkId(4)
    let locators = @[mkLocator(30303), mkLocator(30304)]
    const BnUtf8Tag = @[66'u8, 78'u8]
    var preimage = BnUtf8Tag
    preimage.add(encodeProviderId(provider))
    preimage.add(encodeZkId(zkId))
    preimage.add(encodeLocators(locators))
    let expected = blake2b256Hash(preimage)
    let decl = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: locators,
      providerId: provider,
      zkId: zkId,
      lockedNoteId: default(NoteId),
    )
    check declarationId(decl) == expected

    var wirePreimage = @[encodeServiceTypeAsByte(ServiceType.bn)]
    wirePreimage.add(encodeProviderId(provider))
    wirePreimage.add(encodeZkId(zkId))
    wirePreimage.add(encodeLocators(locators))
    check declarationId(decl) != blake2b256Hash(wirePreimage)

  test "declarationId is independent of mantle wire encoding for ServiceType":
    let provider = mkProvider(1)
    let zkId = seedZkId(2)
    let declare = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: provider,
      zkId: zkId,
      lockedNoteId: default(NoteId),
    )
    let wire = encodeSdpDeclare(declare)
    check wire[0] == encodeServiceTypeAsByte(ServiceType.bn)
    check declarationId(declare) != blake2b256Hash(wire)
    check opId(declare) != declarationId(declare)

{.pop.}
