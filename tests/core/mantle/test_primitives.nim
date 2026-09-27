# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/strutils,
  unittest2,
  libp2p/multiaddress,
  ../../../logos_chain/core/mantle/primitives

suite "core/mantle/primitives":
  test "primitive constants match expected values":
    check MaxBlockTxs == 1024
    check MantleMaxOps == 255

  test "References is MaxBlockTxs of Hash32":
    check default(References).len == MaxBlockTxs

  test "readInputs and readOutputs roundtrip encoders":
    let
      inputs = Inputs(noteIds: @[default(NoteId)])
      inWire = encodeInputs(inputs).get
    var inPos = 0
    check readInputs(inWire, inPos).get == inputs
    check inPos == inWire.len

    let
      outputs = Outputs(notes: @[Note(value: 7, zkPublicKey: default(ZkPublicKey))])
      outWire = encodeOutputs(outputs).get
    var outPos = 0
    check readOutputs(outWire, outPos).get == outputs
    check outPos == outWire.len

  test "encodeServiceType maps BN to wire byte 0":
    check encodeServiceType(ServiceType.bn) == 0'u8
    check encodeServiceType(ServiceType.bn) == byte(ord(ServiceType.bn))

  test "readServiceType parses valid and rejects invalid byte":
    var pos = 0
    check readServiceType(@[encodeServiceType(ServiceType.bn)], pos).get == ServiceType.bn
    check pos == 1
    pos = 0
    check readServiceType(@[99'u8], pos).error == DecodingError.InvalidServiceType

  test "readLocator roundtrips encodeLocator":
    let
      locator = MultiAddress.init("/ip4/127.0.0.1/udp/30303/quic-v1").tryGet()
      wire = encodeLocator(locator).get
    var pos = 0
    let back = readLocator(wire, pos).get
    check pos == wire.len
    check back.data() == locator.data()

  test "encodeInputs returns error on count overflow":
    var largeNotes: seq[NoteId]
    for i in 0 .. 256:
      largeNotes.add default(NoteId)
    check encodeInputs(Inputs(noteIds: largeNotes)).error == EncodingError.InputsCountExceeded

  test "encodeOutputs returns error on count overflow":
    var largeNotes: seq[Note]
    for i in 0 .. 256:
      largeNotes.add default(Note)
    check encodeOutputs(Outputs(notes: largeNotes)).error == EncodingError.OutputsCountExceeded

  test "encodeLocators returns error on count overflow":
    let loc = MultiAddress.init("/ip4/127.0.0.1/udp/30303/quic-v1").tryGet()
    var largeLocs: seq[Locator]
    for i in 0 .. MaxSdpLocators:
      largeLocs.add loc
    check encodeLocators(largeLocs).error == EncodingError.LocatorsCountExceeded

  test "byteLen matches wire length for Inputs, Outputs, and Locator":
    let inputs = Inputs(noteIds: @[default(NoteId), default(NoteId)])
    check byteLen(inputs) == encodeInputs(inputs).get.len
    check byteLen(Inputs(noteIds: @[])) == encodeInputs(Inputs(noteIds: @[])).get.len

    let outputs = Outputs(notes: @[Note(value: 10, zkPublicKey: default(ZkPublicKey))])
    check byteLen(outputs) == encodeOutputs(outputs).get.len
    check byteLen(Outputs(notes: @[])) == encodeOutputs(Outputs(notes: @[])).get.len

    let loc = MultiAddress.init("/ip4/127.0.0.1/udp/30303/quic-v1").tryGet()
    check byteLen(loc) == encodeLocator(loc).get.len

  test "isValidLocator and encodeLocator validate multiaddress length bounds":
    let validLoc = MultiAddress.init("/ip4/127.0.0.1/udp/30303/quic-v1").tryGet()
    check isValidLocator(validLoc)

    let longStr = "/dns4/" & repeat("a", 200) & "/dns4/" & repeat("b", 150)
    let longAddr = MultiAddress.init(longStr).tryGet()
    check not isValidLocator(longAddr)
    check encodeLocator(longAddr).error == EncodingError.LocatorLengthExceeded

  test "encodeLocators roundtrips valid multiple locators":
    let
      loc1 = MultiAddress.init("/ip4/127.0.0.1/tcp/1234").tryGet()
      loc2 = MultiAddress.init("/ip4/10.0.0.1/tcp/8080").tryGet()
      wire = encodeLocators(@[loc1, loc2]).get
    check wire.len == 1 + byteLen(loc1) + byteLen(loc2)
    check wire[0] == 2'u8
    var pos = 1
    check readLocator(wire, pos).get.data() == loc1.data()
    check readLocator(wire, pos).get.data() == loc2.data()
    check pos == wire.len

  test "slotToFr converts slot numbers to BN254 field elements":
    let fr0 = slotToFr(0'u64)
    check fr0 == default(FieldElement)
    let fr42 = slotToFr(42'u64)
    check fr42 != default(FieldElement)

  test "encodeMetadata and encodeInscription roundtrip correctly":
    let meta: Metadata = @[1'u8, 2, 3, 4]
    let encMeta = encodeMetadata(meta).get
    check encMeta.len == 4 + 4 # 4-byte u32 length prefix + 4 payload bytes
    var pos = 0
    check readU32LeLenPrefixed(encMeta, pos).get == meta

    let inscript: Inscription = @[9'u8, 8, 7]
    let encInscript = encodeInscription(inscript).get
    check encInscript.len == 4 + 3
    pos = 0
    check readU32LeLenPrefixed(encInscript, pos).get == inscript

  test "primitive scalar encoders produce exact little-endian byte representations":
    check encodeValue(100'u64) == [100'u8, 0, 0, 0, 0, 0, 0, 0]
    check encodeNonce(42'u64) == [42'u8, 0, 0, 0, 0, 0, 0, 0]
    check encodeOpcode(0x10'u8) == 0x10'u8
    check encodeOpCount(5'u8) == 5'u8
    check encodeSignatureCount(2'u16) == [2'u8, 0]
    check encodeChannelKeyIndex(1'u16) == [1'u8, 0]
    check encodeKeyCount(3'u16) == [3'u8, 0]
    check encodePostingTimeframe(10'u32) == [10'u8, 0, 0, 0]
    check encodePostingTimeout(20'u32) == [20'u8, 0, 0, 0]
    check encodeConfigurationThreshold(2'u16) == [2'u8, 0]
    check encodeTransferThreshold(1'u16) == [1'u8, 0]

    var h: Hash32
    h[0] = 0xAA'u8
    check encodeDeclarationId(h)[0] == 0xAA'u8
    check encodeChannelId(h)[0] == 0xAA'u8
    check encodeParent(h)[0] == 0xAA'u8

    var fe: FieldElement
    fe = slotToFr(123'u64)
    check encodeLockedNoteId(fe) == encodeFieldElement(fe)
    check encodeRewardsRoot(fe) == encodeFieldElement(fe)
    check encodeVoucherNullifier(fe) == encodeFieldElement(fe)
    check encodePublicKey(fe) == encodeZkPublicKey(fe)

  test "readInputs and readOutputs reject truncated data":
    var pos = 0
    # Header says 1 item, but buffer is empty after count byte
    check readInputs(@[1'u8], pos).isErr
    pos = 0
    check readOutputs(@[1'u8], pos).isErr

  test "readLocator rejects invalid multiaddress payload":
    # 2-byte length prefix (len=2), followed by invalid multiaddress bytes [0xFF, 0xFF]
    var invalidWire = @[2'u8, 0, 0xFF'u8, 0xFF'u8]
    var pos = 0
    check readLocator(invalidWire, pos).error == DecodingError.InvalidLocator

  test "readLocator rejects length exceeding MaxLocatorMultiaddrBytes":
    # 2-byte length prefix specifying 330 bytes (> MaxLocatorMultiaddrBytes = 329)
    let lenBytes = encodeLe(uint16(MaxLocatorMultiaddrBytes + 1))
    var wire = @[lenBytes[0], lenBytes[1]]
    for _ in 0 ..< (MaxLocatorMultiaddrBytes + 1):
      wire.add 0'u8
    var pos = 0
    check readLocator(wire, pos).error == DecodingError.LocatorLengthExceeded

  test "readServiceType rejects empty buffer":
    var pos = 0
    check readServiceType(@[], pos).isErr

{.pop.}
