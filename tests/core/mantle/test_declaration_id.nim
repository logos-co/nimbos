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
  ./test_helpers,
  ../../../logos_chain/core/mantle/operations,
  ../../../logos_chain/zk/poseidon2/hasher

suite "core/mantle/operations — declarationId":
  func mkProvider(seed: byte): ProviderId =
    var bytes: array[EdPublicKeySize, byte]
    bytes[0] = seed
    var key: ProviderId
    doAssert key.init(bytes)
    key

  func seedZkId(seed: byte): ZkId =
    var bytes: array[32, byte]
    bytes[0] = seed
    frFromBytesLE(bytes).get

  func seedNoteId(seed: byte): NoteId =
    var bytes: array[32, byte]
    bytes[0] = seed
    frFromBytesLE(bytes).get

  test "declarationId matches the spec vector":
    # Vector from the Declaration Id table of the Mantle Specification
    # v1.18.0:
    # https://github.com/logos-co/logos-lips/blob/6b84187f0ae37a0e8c28c32d3bb1e6f619cec147/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md#declaration-id
    let declaration = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[MultiAddress.init("/ip4/127.0.0.1/udp/3000/quic-v1").get()],
      providerId: mkProvider(1),
      zkId: frFromBytesLE([byte 25]).get,
      lockedNoteId: seedNoteId(26),
    )
    check declarationId(declaration) == hexToByteArray[32](
      "0x67fa7d1fe7f1391195fdd479bba30dd97c9e6d2e1525436ac2427f2bf8567a0d")

  test "declarationId ignores provider, locators and service note":
    # A preimage that holds the provider or the locators fails this.
    let base = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[mkLocator(30303)],
      providerId: mkProvider(1),
      zkId: seedZkId(2),
      lockedNoteId: seedNoteId(1),
    )
    var other = base
    other.locators = @[mkLocator(30304), mkLocator(30305)]
    other.providerId = mkProvider(2)
    other.lockedNoteId = seedNoteId(9)
    check declarationId(other) == declarationId(base)

{.pop.}
