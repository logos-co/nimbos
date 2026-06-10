# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [].}
{.used.}

import std/[os, strutils]
import ../../testutil
import stew/byteutils as byteutils
import results
import bincode

import ../../../logos_chain/core/types
import ../../../logos_chain/chain/genesis
import ../../../logos_chain/core/local_tree
import ../../../logos_chain/deployment/deployment_settings
import ../../../logos_chain/sync/[framing, types, initial_block_download]
import ./helpers

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

  test "GetTip request wire frame is u32 inner length then bincode":
    let inner = try:
      serializeRequestMessageToSeq(RequestMessage(kind: rmGetTip), cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check inner == @[1'u8, 0'u8, 0'u8, 0'u8]
    let lpBody = try:
      addPrefixLengthToPayload(inner)
    except BincodeError as exc:
      fail exc.msg
    check byteutils.toHex(lpBody) == "0400000001000000"
    let backInner = try:
      removePrefixLengthFromPacket(lpBody)
    except BincodeError as exc:
      fail exc.msg
    check backInner == inner

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
    let tip = Tip(tip: bid, slot: SlotNumber(9), height: 123'u64)
    let resp = GetTipResponse(kind: gtrTip, tipData: tip)
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
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    let req = DownloadBlocksRequest(targetBlock: gid, knownBlocks: buildKnownBlocks(tree))
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
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let gid = blockId(genesis.header)
    let tree = newLocalTree(genesis)
    let req = DownloadBlocksRequest(targetBlock: gid, knownBlocks: buildKnownBlocks(tree))
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
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
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

  test "serializeDownloadBlocksResponseToSeq / deserialize (Failure string messages)":
    let cases = @[
      DownloadBlocksResponse(kind: dbrFailure, failureMessage: "example: block not found"),
      DownloadBlocksResponse(kind: dbrFailure, failureMessage: "start block not found"),
      DownloadBlocksResponse(
        kind: dbrFailure, failureMessage: "example: peer reset"),
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

  test "deserialize Rust Failure(String) download response (StartBlockNotFound)":
    const rustInnerHex =
      "0200000033000000000000004661696c656420746f20637265617465206120626c6f636b2073747265616d3a205374617274426c6f636b4e6f74466f756e64"
    let inner = byteutils.hexToSeqByte(rustInnerHex)
    let dec =
      try:
        Opt.some(deserializeDownloadBlocksResponse(inner, cryptarchiaSyncBincodeConfig))
      except BincodeError as exc:
        fail exc.msg
    check dec.isSome
    check dec.get.kind == dbrFailure
    check dec.get.failureMessage ==
      "Failed to create a block stream: StartBlockNotFound"

suite "sync/types (cryptarchia u32 length-prefixed wire fixtures 1-9)":
  test "u32 length-prefixed hex matches cryptarchia sync wire fixtures (1-9)":
    const exp1 = "0400000001000000"
    const exp2 = "3400000000000000abababababababababababababababababababababababababababababababab3930000000000000e703000000000000"
    const exp3 = "240000000100000018000000000000006578616d706c653a2074697020756e617661696c61626c65"
    const exp4 = "6c000000000000001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333330000000000000000"
    const exp5 = "020a000000000000f60900000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000002171571e290ec05f123842aeb111289e325e287e5bb3dbe051faf37c0cb87e2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000007d080000000000000600000da0860100000000006a1aad23fe9bc27c5bce1fdb7aad5d411ee411f7e06ce30dfad620bbd4c26b270100000000000000436f14ef5343e434a3a801aab5f9ae0fcf8d73dedfb86e8fa62c04390a5ef2166400000000000000b00d63129926a40dbadd127364c057bd9af9c0c858ebaa6c146664d3e5ad492fa08601000000000090b90a71381fbab2de62a3ebc9c04c5df5f4a2bed1ef3e63e6f6f2e4d818581c010000000000000061d6d3789378ab1c9fded11088106e0e5b80314cd87998228ceb9988654e192d640000000000000068554f2143b6a9b261af872e04c927401311f7a28e2268237a5b01908e79e328a086010000000000afcd9b6ca5c015471f032a6c608d8d328d34e8fa81e10f1700bc988ed9f02c1a0100000000000000b0bf6597befcf43d29f76834c7da8c79878645692433fa77a09199358829b92c6400000000000000581361fb2ff53fb1778bb9cfcaa9e60495d2584554416efece34b2be98017f12a08601000000000040cfd3e6065a194292a581683bdd94c179f894bbbfd14cee88070beeb3d27d100100000000000000e921b702b4da5da1ff9d834f62f57e3033ff3b6d737e42a6ff9d2cb21b23ce1c6400000000000000fde99f08b1c0c78a3c379255c7ef0ada768ae365d0cef460961cb7c8c6c15518ebe3f9ffffffffff3c3a1f25710bada106a953289964ac1ed66299b85f880f2868e3d3fca99d37181100000000000000000000000000000000000000000000000000000000000000007c0000004c0000000000000070726f636573735f73746172745f6e6f6e63653d313861633632333639393066343137632d30303030303030312c20746573745f656e74726f70793d3631343438613362373963663432613143a9f869000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000010b0004416ccbeb91020d48cd03a725df50280878195d0495943915125087c2ed79e00033c216a48205977403b26da4f0e06a12be4701019ad6c4dbe408c98ed0761e66d678a5add40fdbf6bd040c2910995828e126bf7261240187c84d8b7bb289b99c9849f7afce7af1cd301a2000010b0004416ccbeb91020d49cd038f6b861560bdcca90f63bf695bfe94b24755c8b7b9997656f7a9ca27c97f6dcbfbb2a41a7a0155aeb56c803c968e41e4134871a6812f080436b2a00138a502008ff71d971082290ffdf270e1b9d616f9acd2ca792e0bc68a46a6c01d40e9142a2000010b0004416ccbeb91020d4acd033e557cad40e998678f99f93fe8cba7b13679a0bd44010851de78723729d93ba11e2f1684f4a5d1b9be3b9368eb81bf65b5988bf5ff2c97dadc02afcc50c4470c2d06650ca7fb9c5ef2485ca6788f2778029748bffb7512caab59e4a2e049d9282000010b0004416ccbeb91020d4bcd036b7278c8fe8af5d768a3d729a76b3b7ca33c25c67ed471fbe04f09f8d80539d49c9c111d4e3f7f8f734ce2e489b4c7f0581d73bc171cee91db39802f300e8e2f6d5e340340bb6f669a0b4b350d7bed7428aec44d2e9059a2f0fb510954497800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005eccc2c6c6d168afd017ec7f0c27168b281a59d3913a6c75d446000f29cfba8ed29d85b0091375adbdbe735faf9bd42ec095d1d97b93146f210f792036f951026f7078a40b055f0c470eb8ed1ca524370d1413384912ae5713dbdff99b8c57054a06a4f42b4833fb35bfbc524f06d9a4a536eb1009096451091da9aa0c3bfe83efb6fce6f6d2cbc4568cdc6908fb2073026a00473c1dc526f56645f45bbbd0fe9cd0ef7a0cd415ed503fc1296c4753ed621e52bfb03c6513d381fb20e28662098866d20fc23ea5021c96124f19d8d0736edfe28aa80ab28023177b4ca8d994ab4ae060a9cf67e3070558496a69ca17c2834252304e21d437526e389dfc593f199eaf6ff120292d43cab9f01c187375b0eb4035198e60973f0d88498f2379ba9a862f3e4762b67b94c5e8765de691fd4989856b11d4359147a85316435901c99d5535d99990503b9d1565b3a4fec964dbed49905be44477e904867cc6f4835e8e666937845c6bf98d3bbee15f8fbbe0ee14b2c48935611ed17208c7edbf821e02dad0b00e7b5c5c5987130aea6fa1eb10faff4610ffec6e457ebc1fb91c0b610d74de33431b9c76028eee1c24122c9b7ec38f783eaa11f0d51507e74f058da4042b0d617f2bf231398cbb4e97a2ac7f17649bcde913d9faab2221013519684611e59b31f079094dfdbc4b1cd375cebe647c12009f84a0e467ed538bf473ea6f272da88f545894ea09aabd829a5f63b38cff20d2e3ac8cf1a06d2efc8c8ad62128cdf02494c71cbf61f32441b5b2552fa3d5f33410186047f6dd6ee6aa1da4aa0dcc690433b83d7bd59e3a36f16e723849b5bc6bd1ddcfbe020cd2a0d0e2bc14a5cd6fa7ade727a77aca70cbbd4b958c18a9ea08fd867ab94e3f5b553d94489d01d4386e54180cec1b78dfdcd6e2516d324702f3bd4fa95bfaf0e16ab651cf7f950700f95a721c94106eaebb299128fcf9bc2e7c6961b5f2c0a51c2e46ef770c2703c8244f57448e98d09deccaeb76e465dea2e30c5dae1a40cefdab20f3da9f2804c59d51037b7da1363943c296e1bb6cf8743cf327f2bd8b43d4a262e0ac8504"
    const exp6 = "0400000001000000"
    const exp7 = "240000000200000018000000000000006578616d706c653a20626c6f636b206e6f7420666f756e64"
    const exp8 = "21000000020000001500000000000000737461727420626c6f636b206e6f7420666f756e64"
    const exp9 = "1f0000000200000013000000000000006578616d706c653a2070656572207265736574"

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
          kind: dbrFailure, failureMessage: "example: block not found"),
        cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check u32LengthPrefixedHex(inner7) == exp7

    let inner8 = try:
      serializeDownloadBlocksResponseToSeq(DownloadBlocksResponse(
          kind: dbrFailure, failureMessage: "start block not found"),
        cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check u32LengthPrefixedHex(inner8) == exp8

    let inner9 = try:
      serializeDownloadBlocksResponseToSeq(DownloadBlocksResponse(
          kind: dbrFailure, failureMessage: "example: peer reset"),
        cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check u32LengthPrefixedHex(inner9) == exp9

{.pop.}
