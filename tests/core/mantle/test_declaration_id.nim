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
  stew/byteutils,
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

    let idA = declarationId(base).get
    let idB = declarationId(base).get
    let idC = declarationId(otherNote).get
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
    )).get
    check base != declarationId(DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: locators,
      providerId: mkProvider(2),
      zkId: zkId,
      lockedNoteId: default(NoteId),
    )).get
    check base != declarationId(DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: locators,
      providerId: provider,
      zkId: seedZkId(3),
      lockedNoteId: default(NoteId),
    )).get
    check base != declarationId(DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[mkLocator(30304)],
      providerId: provider,
      zkId: zkId,
      lockedNoteId: default(NoteId),
    )).get

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
    preimage.add(encodeLocators(decl.locators).get)
    check declarationId(decl).get == blake2b256Hash(preimage)

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
    check declarationId(declare).get != blake2b256Hash(encodeSdpDeclare(declare).get)
    check opId(declare).get != declarationId(declare).get

  test "declarationId matches the spec vector":
    # Vector from the Declaration Id table of the Mantle Specification
    # v1.17.0:
    # https://github.com/logos-co/logos-lips/blob/949faa9563027de366514247a2a62b0de2f8c45f/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md
    var provider: ProviderId
    check provider.init(hexToByteArray[32](
      "0x53470962558a6e0839022ae65c6b2723b32772e5c0c5f4776cb8e6a3e10ba2f3"))
    let
      locators = @[
        MultiAddress.init("/ip4/127.0.0.1/udp/3000/quic-v1").get()]
      declaration = DeclarationMessage(
        serviceType: ServiceType.bn,
        locators: locators,
        providerId: provider,
        zkId: frFromBytesLE([byte 25]).get,
        lockedNoteId: default(NoteId),
      )
    check encodeServiceType(declaration.serviceType) == 0x00'u8
    check encodeZkId(declaration.zkId) == hexToByteArray[32](
      "0x1900000000000000000000000000000000000000000000000000000000000000")
    check encodeLocators(locators).get ==
      hexToSeqByte("0x010b00047f00000191020bb8cd03")
    # The spec preimage row, assembled by hand on purpose.
    var preimage = @[encodeServiceType(declaration.serviceType)]
    preimage.add(encodeProviderId(declaration.providerId))
    preimage.add(encodeZkId(declaration.zkId))
    preimage.add(encodeLocators(locators).get)
    check preimage == hexToSeqByte(
      "0x0053470962558a6e0839022ae65c6b2723b32772e5c0c5f4776cb8e6a3e10ba2f3" &
      "1900000000000000000000000000000000000000000000000000000000000000" &
      "010b00047f00000191020bb8cd03")
    check declarationId(declaration).get == hexToByteArray[32](
      "0x7fb647c069bade94e06685b0825299d220e7cc14752cfc474773b6c4040e37b5")

{.pop.}
