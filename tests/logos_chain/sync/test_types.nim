# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [].}
{.used.}

import std/[os, strutils]
import std/options
import unittest2
import stew/byteutils as byteutils
import results

import "../../../logos_chain/core/types"
import "../../../logos_chain/chain/genesis"
import "../../../logos_chain/core/local_tree"
import ../../../logos_chain/deployment/deployment_settings
import "../../../logos_chain/sync"/[config, types, initial_block_download]
import ./helpers

from "../../../logos_chain/core/mantle/primitives" import SlotNumber

const testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
const deploymentSettingsPath = testsDir / "../../../config/deployment-settings.yaml"

suite "sync/types (GetTip RequestMessage / response wire)":
  test "GetTip request body is RequestMessage GetTip bincode discriminant (u32 LE = 1)":
    let body = try:
      serializeRequestMessageToSeq(RequestMessage(kind: rmGetTip), cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    check body.len == 4
    check body == @[1'u8, 0'u8, 0'u8, 0'u8]
    let m = try:
      some(deserializeRequestMessage(body, cryptarchiaSyncBincodeConfig))
    except CatchableError:
      none(RequestMessage)
    check m.isSome and m.get.kind == rmGetTip

  test "GetTip request writeLp body is u32 inner length then bincode (libp2p varint wraps that)":
    let inner = try:
      serializeRequestMessageToSeq(RequestMessage(kind: rmGetTip), cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    check inner == @[1'u8, 0'u8, 0'u8, 0'u8]
    let lpBody = try:
      addPrefixLengthToPayload(inner)
    except CatchableError:
      @[]
    check byteutils.toHex(lpBody) == "0400000001000000"
    let backInner = try:
      removePrefixLengthFromPacket(lpBody)
    except CatchableError:
      @[]
    check backInner == inner

  test "serializeRequestMessageToSeq(GetTip RequestMessage) inner bincode hex":
    let body =
      try:
        serializeRequestMessageToSeq(RequestMessage(kind: rmGetTip), cryptarchiaSyncBincodeConfig)
      except CatchableError:
        @[]
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
    except CatchableError:
      @[]
    let d = try:
      some(deserializeGetTipResponse(wire, cryptarchiaSyncBincodeConfig))
    except CatchableError:
      none(GetTipResponse)
    check d.isSome and d.get.kind == gtrTip and d.get.tipData == tip

  test "GetTip failure response roundtrips":
    let resp = GetTipResponse(kind: gtrFailure, failureMessage: "no tip for you")
    let wire = try:
      serializeGetTipResponseToSeq(resp, cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    let d = try:
      some(deserializeGetTipResponse(wire, cryptarchiaSyncBincodeConfig))
    except CatchableError:
      none(GetTipResponse)
    check d.isSome and d.get.kind == gtrFailure and d.get.failureMessage == "no tip for you"

  test "Fixture GetTipResponse Tip wire roundtrips":
    let tip = exampleGetTipTipFixture()
    check tip.tip[0] == 0xAB'u8 and tip.tip[^1] == 0xAB'u8
    check tip.slot == SlotNumber(12_345'u64) and tip.height == 999'u64
    let wOpt = exampleSerializedGetTipResponseTipWire()
    check wOpt.isSome
    let wire = wOpt.get
    let d = try:
      some(deserializeGetTipResponse(wire, cryptarchiaSyncBincodeConfig))
    except CatchableError:
      none(GetTipResponse)
    check d.isSome and d.get.kind == gtrTip and d.get.tipData == tip

  test "Example GetTipResponse Failure wire roundtrips":
    let wOpt = exampleSerializedGetTipResponseFailureWire("example: tip unavailable")
    check wOpt.isSome
    let wire = wOpt.get
    let d = try:
      some(deserializeGetTipResponse(wire, cryptarchiaSyncBincodeConfig))
    except CatchableError:
      none(GetTipResponse)
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
    except CatchableError:
      @[]
    let dec =
      try:
        some(deserializeDownloadBlocksRequest(inner, cryptarchiaSyncBincodeConfig))
      except CatchableError:
        none(DownloadBlocksRequest)
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
    except CatchableError:
      @[]
    check wire.len >= 4
    let m =
      try:
        some(deserializeRequestMessage(wire, cryptarchiaSyncBincodeConfig))
      except CatchableError:
        none(RequestMessage)
    check m.isSome and m.get.kind == rmDownloadBlocksRequest
    check downloadBlocksRequestEqual(m.get.downloadBlocksRequest, req)

  test "serializeDownloadBlocksResponseToSeq / deserializeDownloadBlocksResponse roundtrip (NoMore)":
    let msg = DownloadBlocksResponse(kind: dbrNoMoreBlocks)
    let inner = try:
      serializeDownloadBlocksResponseToSeq(msg, cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    let dec =
      try:
        some(deserializeDownloadBlocksResponse(inner, cryptarchiaSyncBincodeConfig))
      except CatchableError:
        none(DownloadBlocksResponse)
    check dec.isSome and downloadBlocksResponseEqual(dec.get, msg)

  test "serializeDownloadBlocksResponseToSeq / deserializeDownloadBlocksResponse roundtrip (one block)":
    let sm = minimalSignedTx()
    let genesis = createGenesisBlock(sm)
    let blockWire = try:
      serializeBlockToSeq(genesis, cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    let msg = DownloadBlocksResponse(kind: dbrBlock, downloadedBlock: blockWire)
    let inner = try:
      serializeDownloadBlocksResponseToSeq(msg, cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    let backOpt =
      try:
        some(deserializeDownloadBlocksResponse(inner, cryptarchiaSyncBincodeConfig))
      except CatchableError:
        none(DownloadBlocksResponse)
    check backOpt.isSome
    let back = backOpt.get
    check back.kind == dbrBlock
    let blksOpt = decodeBlocksFromDownloadResponses(@[back])
    check blksOpt.isSome and blksOpt.unsafeGet.len == 1
    check blockId(blksOpt.unsafeGet[0].header) == blockId(genesis.header)

  test "serializeDownloadBlocksResponseToSeq / deserialize (Failure BlockNotFound + Start + Unknown)":
    var miss: BlockId
    miss[0] = 0x01'u8
    miss[^1] = 0xFF'u8
    let cases = @[
      DownloadBlocksResponse(kind: dbrFailure, failureReason: BlocksUnavailableReason(
        kind: burBlockNotFound, blockNotFoundId: miss)),
      DownloadBlocksResponse(kind: dbrFailure, failureReason: BlocksUnavailableReason(kind: burStartBlockNotFound)),
      DownloadBlocksResponse(
        kind: dbrFailure, failureReason: BlocksUnavailableReason(kind: burUnknown,
          unknownMessage: "chain unavailable")),
    ]
    for msg in cases:
      let inner = try:
        serializeDownloadBlocksResponseToSeq(msg, cryptarchiaSyncBincodeConfig)
      except CatchableError:
        @[]
      let dec =
        try:
          some(deserializeDownloadBlocksResponse(inner, cryptarchiaSyncBincodeConfig))
        except CatchableError:
          none(DownloadBlocksResponse)
      check dec.isSome and downloadBlocksResponseEqual(dec.get, msg)

suite "sync/types (cryptarchia LP-prefixed wire vs nimbus_beacon_node samples 1-9)":
  test "prefixed LP hex matches nimbus_beacon_node startup logging targets (1-9)":
    const exp1 = "0400000001000000"
    const exp2 = "3400000000000000abababababababababababababababababababababababababababababababab3930000000000000e703000000000000"
    const exp3 = "240000000100000018000000000000006578616d706c653a2074697020756e617661696c61626c65"
    const exp4 = "6c000000000000001111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333330000000000000000"
    const exp5 = "ee09000000000000e209000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000039d5d7a9ff20af4ab3dbee2f2e8a1035e785615059bc7b1f2e7349e17b4e8d2f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000a9080000000000000600000da086010000000000f1a57ec7b85a73636372239c081f7b8986d81c82e3edadd7c50b13f8d6b098080100000000000000d114b1cbaf0e0b10d00449a3e0fcd789710a0bf9c63de9185c07e573144bde086400000000000000859d98b2eb9f6253bf908ca2b1fc445b517b7cb5e7b6280e2c1da4f19304c71da0860100000000007da3dd5d15672d6f6ebc6378d3b7f8e818b1b719b1e88f96a08ca1b3175130190100000000000000de0547b5c5cb44f7a3b156d757087a6e4b23e977fde1e0cc133823e39ac6832764000000000000007215983b8b7440c7bc61a8252f1d6cb5f6cd2c8e098b9dc17a43145af93d1900a086010000000000dfc3c8e7d28ac773a17919a5567d427e1a2786ef3355201285da209bbefff61d0100000000000000b64e26c88f58b4a6096a6e5b98b4365355c294835eee8cec58356c1d6b4b85026400000000000000670b1a36742173c0310ec3ffb352afe8430d938619334ce57a8fb2bcd24dca1ea086010000000000ac2d8fce76640804e05a6e1f5da5a0ae784e05a5d1b9f917872cf8664f6bce1c010000000000000090678379b2ed5316d870eb51e8c20ffaf891ade0ed80a8775f4136a8979fac276400000000000000605199d3e793d342f1f0457c0ada288efc61d455e3b576e70af14b1651a08c06ebe3f9fffffffffffcadf75488f8048bd4db210e55b6da2c1960af0fda9c3ce73bb79b842c688a141100000000000000000000000000000000000000000000000000000000000000004c00000070726f636573735f73746172745f6e6f6e63653d313861356633623230373736393732372d30303030303030312c20746573745f656e74726f70793d363134343861336237396366343261310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000122002f6970342f36352e3130392e35312e33372f7564702f333430302f717569632d763159c662860b737f4e2515599adb3434856db8070b373a449ff66955ad3da6b4736b2bcd3029fba573cff0c332dc4de7430faf5e261383d693d8dbb5b97665660a3683046167f2329c325bc49b692f8530775a0ea552d5059b8c5b05ee6d1ca81220000122002f6970342f36352e3130392e35312e33372f7564702f333430312f717569632d76317fce82aa171b349a40f2a98ce9a05b5db62415adfd3ab4ffea6f214443d5909dae9a47f76c9a2c00c40310cc82a1da9f5292af9ee223b898c38478c85fd3951547aeab97e93399a1c3411ab1743b73856c91a6c23e5efc3187f4aa1aec39481b20000122002f6970342f36352e3130392e35312e33372f7564702f333430322f717569632d7631da8060ee71506bcbf1ac50973ad6dedc3a6cae69139b9d12bfd9c80c4785f6b04114009ea9da81c5fcb680eca33129fb3fe166af733d25a23ac2da567ee84c191cdca82d608dd462963b319eb183bfc94d835571cc7834df376fbc1d64ab730920000122002f6970342f36352e3130392e35312e33372f7564702f333430332f717569632d7631f6807fc50fbd4ef5f7fe1aaef037ee78d23233e60de802da36bfbb64215800fe4d705c711b7c99fc041576c0c5412934cd86f3369d88c9f451e786c0e396fb1c7eb3dc8ec6d00ebf6e3a203d5c0c46937092c75fed5140ee6a23a0530641c30200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d75e9b70e8356eee47db4a4afe1f0c5ec4722063de35b7e2d00b07124933b29c4932ae1e89d53f7ee06bf40fdb60c3b38ea762d00e8efbf5128b4230840f6902ff0ce74eea14cdaccf716487594e6ab06a9648786ecbb23ff49a4f421fbb42a76bcde9760ceba1d4623a44c9dfb9d32c1e79151049436dc3cf3b160bb8059a003a3b81bc992241a19b9ed4020a391ebd318db067e5af24c8c697b2249a2b330d506913be83ceeb4235a62b9135cd8e5697309a3e92b780e974557d2341fec6037f1178fb8131c1896257211ccc9dbeb614cbe81da7c4d018daf9e5fb9485c5115eb626a1bfc43c44be1f1d2db4a6c971fffafec24b335d1f4d571fe670b2f60e52c808c0a6a30947047c093775778f656720123c4957bac29b230a0ef924c78126522e78daf38e846f5b75e5d8a3cb6d9032e45fa693ba0bb6373fc12f216e217b1568fba65308504498e5bf9284f75a545439bd3d76e534460ac63990854c607e0bd65e6af79225236c80b2def4168a35eb71669a1c3f1555ce1dcac7ac4c0145c89c04f4ecf3e38955056b981cd73ca2ce9785f1422e58253c85f500b8dda0f3802fc4008925ed9101ecd2c82ab714bd4b05405fe76a183eba829a7800a40f165b1fe424d43e6823c6edb4d3175259868afe84180602aed13ada849155ef08693036f564a705a2909942a813d9efd22413c419c20e853956ce7a85e0e93f0317c29bd38e0d030d6800cdefa58765b768182252805cd240372f5b43c15bfd0921b2ea30a774179c52781930a60fb707372cd9f9b464e59a2b2771ee5db8ee00fda3ba7b8d786b6de0773bd81345e5c8c2d2da2dc89762e2bdd00f5d3d361f0d23832c37b97bcad9af05a1aa4d0a3445e9581c6f22f80633e59c39d4c88e7a15f364c87b4693d2dbd3abd91702fe95cae5f90fd58a6c29db654f4b3d3ca3679c28b9196a4229127c902c7ee13cc969331c9b6dc77c3e671f48796adeb1334118a3a618d710dd1b14e07ac130ecac3702c24d6db2632907061b9e6baedfc9f6719dd97bd8db337669fe085c23df7334278d3139f396dc82beaf844affa378e208"
    const exp6 = "0400000001000000"
    const exp7 = "280000000200000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    const exp8 = "080000000200000001000000"
    const exp9 = "23000000020000000200000013000000000000006578616d706c653a2070656572207265736574"

    let inner1 = try:
      serializeRequestMessageToSeq(RequestMessage(kind: rmGetTip), cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    check lpPrefixedHex(inner1) == exp1

    let inner2 = try:
      serializeGetTipResponseToSeq(
        GetTipResponse(kind: gtrTip, tipData: exampleGetTipTipFixture()),
        cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    check lpPrefixedHex(inner2) == exp2

    let inner3 = try:
      serializeGetTipResponseToSeq(GetTipResponse(
          kind: gtrFailure, failureMessage: "example: tip unavailable"),
        cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    check lpPrefixedHex(inner3) == exp3

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
    except CatchableError:
      @[]
    check lpPrefixedHex(inner4) == exp4

    let pr = parseDeploymentSettings(readFile(deploymentSettingsPath))
    require pr.isOk
    let genesisFromDeployment =
      createGenesisBlock(pr.get.cryptarchia.genesisState.signedMantleTx)
    let genesisWire = try:
      serializeBlockToSeq(genesisFromDeployment, cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    let inner5 = try:
      serializeDownloadBlocksResponseToSeq(DownloadBlocksResponse(
          kind: dbrBlock, downloadedBlock: genesisWire),
        cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    check lpPrefixedHex(inner5) == exp5

    let inner6 = try:
      serializeDownloadBlocksResponseToSeq(DownloadBlocksResponse(kind: dbrNoMoreBlocks),
        cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    check lpPrefixedHex(inner6) == exp6

    let inner7 = try:
      serializeDownloadBlocksResponseToSeq(DownloadBlocksResponse(
          kind: dbrFailure, failureReason: BlocksUnavailableReason(
            kind: burBlockNotFound, blockNotFoundId: exampleBlockId(0xEE))),
        cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    check lpPrefixedHex(inner7) == exp7

    let inner8 = try:
      serializeDownloadBlocksResponseToSeq(DownloadBlocksResponse(
          kind: dbrFailure, failureReason: BlocksUnavailableReason(kind: burStartBlockNotFound)),
        cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    check lpPrefixedHex(inner8) == exp8

    let inner9 = try:
      serializeDownloadBlocksResponseToSeq(DownloadBlocksResponse(
          kind: dbrFailure, failureReason: BlocksUnavailableReason(
            kind: burUnknown, unknownMessage: "example: peer reset")),
        cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    check lpPrefixedHex(inner9) == exp9

{.pop.}
