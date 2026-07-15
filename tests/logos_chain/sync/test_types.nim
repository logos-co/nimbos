# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [].}
{.used.}

import
  std/[os, strutils],
  ../../testutil,
  stew/byteutils as byteutils,
  results,
  bincode,
  ../../../logos_chain/core/[types, local_tree],
  ../../../logos_chain/chain/genesis,
  ../../../logos_chain/deployment/deployment_settings,
  ../../../logos_chain/sync/[types, ibd_client],
  ./helpers
from ../../../logos_chain/core/mantle/primitives import SlotNumber

const testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
const deploymentSettingsPath = testsDir / "../../../config/deployment-settings.yaml"

suite "sync/types (GetTip RequestMessage / response wire)":
  test "GetTip request body is RequestMessage GetTip bincode discriminant (u32 LE = 1)":
    let body = try:
      serializeRequestMessageToSeq(RequestMessage(kind: rmGetTip), cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check body.len == 4
    check body == @[1'u8, 0'u8, 0'u8, 0'u8]
    let m = try:
      Opt.some(deserializeRequestMessage(body, cryptarchiaSyncBincodeConfig))
    except BincodeError as exc:
      fail exc.msg
    check m.isSome and m.get.kind == rmGetTip

  test "serializeRequestMessageToSeq(GetTip RequestMessage) inner bincode hex":
    let body =
      try:
        serializeRequestMessageToSeq(RequestMessage(kind: rmGetTip), cryptarchiaSyncBincodeConfig)
      except BincodeError, IOError:
        fail getCurrentExceptionMsg()
    check byteutils.toHex(body) == "01000000"

  test "Example GetTipResponse Tip wire (tip=[0xAB;32], slot=12345, height=999)":
    let wOpt = exampleSerializedGetTipResponseTipWire()
    check wOpt.isSome
    check byteutils.toHex(wOpt.get) ==
      "00000000abababababababababababababababababababababababababababababababab3930000000000000e703000000000000"

  test "Example GetTipResponse Failure wire (example: tip unavailable)":
    let wOpt = exampleSerializedGetTipResponseFailureWire("example: tip unavailable")
    check wOpt.isSome
    check byteutils.toHex(wOpt.get) ==
      "0100000018000000000000006578616d706c653a2074697020756e617661696c61626c65"

  test "Tip response roundtrips (success variant)":
    var bid: BlockId
    bid[0] = 7'u8
    bid[31] = 42'u8
    let
      tip = Tip(tip: bid, slot: SlotNumber(9), height: 123'u64)
      resp = GetTipResponse(kind: gtrTip, tipData: tip)
    let wire = try:
      serializeGetTipResponseToSeq(resp, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    let d = try:
      Opt.some(deserializeGetTipResponse(wire, cryptarchiaSyncBincodeConfig))
    except BincodeError as exc:
      fail exc.msg
    check d.isSome and d.get.kind == gtrTip and d.get.tipData == tip

  test "GetTip failure response roundtrips":
    let resp = GetTipResponse(kind: gtrFailure, failureMessage: "no tip for you")
    let wire = try:
      serializeGetTipResponseToSeq(resp, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    let d = try:
      Opt.some(deserializeGetTipResponse(wire, cryptarchiaSyncBincodeConfig))
    except BincodeError as exc:
      fail exc.msg
    check d.isSome and d.get.kind == gtrFailure and d.get.failureMessage == "no tip for you"

  test "Fixture GetTipResponse Tip wire roundtrips":
    let tip = exampleGetTipTipFixture()
    check tip.tip[0] == 0xAB'u8 and tip.tip[^1] == 0xAB'u8
    check tip.slot == SlotNumber(12_345'u64) and tip.height == 999'u64
    let wOpt = exampleSerializedGetTipResponseTipWire()
    check wOpt.isSome
    let wire = wOpt.get
    let d = try:
      Opt.some(deserializeGetTipResponse(wire, cryptarchiaSyncBincodeConfig))
    except BincodeError as exc:
      fail exc.msg
    check d.isSome and d.get.kind == gtrTip and d.get.tipData == tip

  test "Example GetTipResponse Failure wire roundtrips":
    let wOpt = exampleSerializedGetTipResponseFailureWire("example: tip unavailable")
    check wOpt.isSome
    let wire = wOpt.get
    let d = try:
      Opt.some(deserializeGetTipResponse(wire, cryptarchiaSyncBincodeConfig))
    except BincodeError as exc:
      fail exc.msg
    check d.isSome and d.get.kind == gtrFailure and d.get.failureMessage == "example: tip unavailable"

suite "sync/types (download RequestMessage / request & response payloads)":
  test "serializeDownloadBlocksRequestToSeq / deserializeDownloadBlocksRequest roundtrip":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
      req = DownloadBlocksRequest(targetBlock: gid, knownBlocks: buildKnownBlocks(tree))
    let inner = try:
      serializeDownloadBlocksRequestToSeq(req, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    let dec =
      try:
        Opt.some(deserializeDownloadBlocksRequest(inner, cryptarchiaSyncBincodeConfig))
      except BincodeError as exc:
        fail exc.msg
    check dec.isSome and downloadBlocksRequestEqual(dec.get, req)

  test "RequestMessage download discriminant roundtrips":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
      req = DownloadBlocksRequest(targetBlock: gid, knownBlocks: buildKnownBlocks(tree))
    let wire = try:
      serializeRequestMessageToSeq(
        RequestMessage(kind: rmDownloadBlocksRequest, downloadBlocksRequest: req),
        cryptarchiaSyncBincodeConfig,
      )
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check wire.len >= 4
    let m =
      try:
        Opt.some(deserializeRequestMessage(wire, cryptarchiaSyncBincodeConfig))
      except BincodeError as exc:
        fail exc.msg
    check m.isSome and m.get.kind == rmDownloadBlocksRequest
    check downloadBlocksRequestEqual(m.get.downloadBlocksRequest, req)

  test "serializeDownloadBlocksResponseToSeq / deserializeDownloadBlocksResponse roundtrip (NoMore)":
    let msg = DownloadBlocksResponse(kind: dbrNoMoreBlocks)
    let inner = try:
      serializeDownloadBlocksResponseToSeq(msg, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    let dec =
      try:
        Opt.some(deserializeDownloadBlocksResponse(inner, cryptarchiaSyncBincodeConfig))
      except BincodeError as exc:
        fail exc.msg
    check dec.isSome and downloadBlocksResponseEqual(dec.get, msg)

  test "serializeDownloadBlocksResponseToSeq / deserializeDownloadBlocksResponse roundtrip (one block)":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
    let blockWire = try:
      serializeBlockToSeq(genesis, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    let msg = DownloadBlocksResponse(kind: dbrBlock, downloadedBlock: blockWire)
    let inner = try:
      serializeDownloadBlocksResponseToSeq(msg, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    let backOpt =
      try:
        Opt.some(deserializeDownloadBlocksResponse(inner, cryptarchiaSyncBincodeConfig))
      except BincodeError as exc:
        fail exc.msg
    check backOpt.isSome
    let back = backOpt.get
    check back.kind == dbrBlock
    let blksOpt = decodeBlocksFromDownloadResponses(@[back])
    check blksOpt.isSome and blksOpt.unsafeGet.len == 1
    check blockId(blksOpt.unsafeGet[0].header) == blockId(genesis.header)

  test "serializeDownloadBlocksResponseToSeq / deserialize (Failure reasons)":
    let cases = @[
      DownloadBlocksResponse(
        kind: dbrFailure,
        blocksUnavailableReason: BlocksUnavailableReason(
          kind: burBlockNotFound, headerId: exampleBlockId(0x04'u8))),
      DownloadBlocksResponse(
        kind: dbrFailure,
        blocksUnavailableReason: BlocksUnavailableReason(kind: burStartBlockNotFound)),
      DownloadBlocksResponse(
        kind: dbrFailure,
        blocksUnavailableReason: BlocksUnavailableReason(
          kind: burUnknown, message: "example: download failed")),
    ]
    for msg in cases:
      let inner = try:
        serializeDownloadBlocksResponseToSeq(msg, cryptarchiaSyncBincodeConfig)
      except BincodeError, IOError:
        fail getCurrentExceptionMsg()
      let dec =
        try:
          Opt.some(deserializeDownloadBlocksResponse(inner, cryptarchiaSyncBincodeConfig))
        except BincodeError as exc:
          fail exc.msg
      check dec.isSome and downloadBlocksResponseEqual(dec.get, msg)

  test "deserialize Rust Failure(Unknown) download response":
    const rustInnerHex =
      "020000000200000033000000000000004661696c656420746f20637265617465206120626c6f636b2073747265616d3a205374617274426c6f636b4e6f74466f756e64"
    let
      inner = byteutils.hexToSeqByte(rustInnerHex)
      dec =
        try:
          Opt.some(deserializeDownloadBlocksResponse(inner, cryptarchiaSyncBincodeConfig))
        except BincodeError as exc:
          fail exc.msg
    check dec.isSome
    check dec.get.kind == dbrFailure
    check dec.get.blocksUnavailableReason.kind == burUnknown
    check dec.get.blocksUnavailableReason.message ==
      "Failed to create a block stream: StartBlockNotFound"

suite "sync/types (cryptarchia u32 length-prefixed wire fixtures 1-9)":
  test "u32 length-prefixed hex matches cryptarchia sync wire fixtures (1-9)":
    const exp1 = "0400000001000000"
    const exp2 = "3400000000000000abababababababababababababababababababababababababababababababab3930000000000000e703000000000000"
    const exp3 = "240000000100000018000000000000006578616d706c653a2074697020756e617661696c61626c65"
    const exp4 = "6c000000000000001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333330000000000000000"
    const exp5 = "e204000000000000d60400000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000007d3a7840601116778cda80fe20ebc0aed85018cbc7535b768c7f40168373af6700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000005d0300000000000003000005a086010000000000e3635f207984ae779cf76b5f20714b514373f61ff96260879fe0a6d71f2dce07640000000000000039e16b432574571a6bcd8ee36e370589641bd9f35367f6f97a972453c46c322564000000000000009750fa86471fddc69749aa9f8568ef6635e64d9f9aa815e8cb932cea183c8e180100000000000000852efb444db8c3c811625850df39425f43aeffc69571192c0be9f72523256e0affffffffffffffffd2a1977db29daf6691f7ce897fe7b666ec964b1bf027814cacd1a2c141b12f101100000000000000000000000000000000000000000000000000000000000000003c00000010000000000000007374616e64616c6f6e652d6c6f63616c9169fe692d2ddf918544bca603c5a291c7dd1b902d6769ff4b00021506780e075c06051a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000010b00047f00000191020d48cd03aa70aafc48536ae13168ed4845981a40cbd2dc1c38df88d04c46250e9ad65ce0852efb444db8c3c811625850df39425f43aeffc69571192c0be9f72523256e0aa4405fdbd782bd39c4e388ac470c98fdca3e9edfdf7d2672bc63223d75dab721000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    const exp6 = "0400000001000000"
    const exp7 = "2800000002000000000000000404040404040404040404040404040404040404040404040404040404040404"
    const exp8 = "080000000200000001000000"
    const exp9 = "28000000020000000200000018000000000000006578616d706c653a20646f776e6c6f6164206661696c6564"

    let inner1 = try:
      serializeRequestMessageToSeq(RequestMessage(kind: rmGetTip), cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check u32LengthPrefixedHex(inner1) == exp1

    let inner2 = try:
      serializeGetTipResponseToSeq(
        GetTipResponse(kind: gtrTip, tipData: exampleGetTipTipFixture()),
        cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check u32LengthPrefixedHex(inner2) == exp2

    let inner3 = try:
      serializeGetTipResponseToSeq(GetTipResponse(
          kind: gtrFailure, failureMessage: "example: tip unavailable"),
        cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check u32LengthPrefixedHex(inner3) == exp3

    let dlReqMsg = RequestMessage(
      kind: rmDownloadBlocksRequest,
      downloadBlocksRequest: DownloadBlocksRequest(
        targetBlock: exampleBlockId(0x11),
        knownBlocks: KnownBlocks(
          localTip: exampleBlockId(0x22),
          latestImmutableBlock: exampleBlockId(0x33),
          additionalBlocks: @[],
        ),
      ))
    let inner4 = try:
      serializeRequestMessageToSeq(dlReqMsg, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check u32LengthPrefixedHex(inner4) == exp4

    let pr = parseDeploymentSettings(readFile(deploymentSettingsPath))
    require pr.isOk
    let genesisFromDeployment =
      createGenesisBlock(pr.get.cryptarchia.genesisState.signedMantleTx)
    let genesisWire = try:
      serializeBlockToSeq(genesisFromDeployment, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    let inner5 = try:
      serializeDownloadBlocksResponseToSeq(DownloadBlocksResponse(
          kind: dbrBlock, downloadedBlock: genesisWire),
        cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check u32LengthPrefixedHex(inner5) == exp5

    let inner6 = try:
      serializeDownloadBlocksResponseToSeq(DownloadBlocksResponse(kind: dbrNoMoreBlocks),
        cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check u32LengthPrefixedHex(inner6) == exp6

    let inner7 = try:
      serializeDownloadBlocksResponseToSeq(DownloadBlocksResponse(
          kind: dbrFailure,
          blocksUnavailableReason: BlocksUnavailableReason(
            kind: burBlockNotFound, headerId: exampleBlockId(0x04'u8))),
        cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check u32LengthPrefixedHex(inner7) == exp7

    let inner8 = try:
      serializeDownloadBlocksResponseToSeq(DownloadBlocksResponse(
          kind: dbrFailure,
          blocksUnavailableReason: BlocksUnavailableReason(kind: burStartBlockNotFound)),
        cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check u32LengthPrefixedHex(inner8) == exp8

    let inner9 = try:
      serializeDownloadBlocksResponseToSeq(DownloadBlocksResponse(
          kind: dbrFailure,
          blocksUnavailableReason: BlocksUnavailableReason(
            kind: burUnknown, message: "example: download failed")),
        cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check u32LengthPrefixedHex(inner9) == exp9

{.pop.}
