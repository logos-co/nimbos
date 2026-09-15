# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  std/sequtils,
  results,
  bincode,
  libp2p/[switch, errors],
  stew/byteutils as byteutils,
  ../../testutil,
  ../../ledger/sdp/test_helpers,
  ../../../logos_chain/chain/[chain, block_processor],
  ../../../logos_chain/core/[types, local_tree],
  ../../../logos_chain/ledger/ledger,
  ../../../logos_chain/sync/[framing, types, ibd_client, ibd_server, syncer]
from ../../../logos_chain/core/mantle/primitives import SlotNumber
from ../../../logos_chain/core/mantle/tx_types import SignedMantleTx, encodeSignedMantleTx
from ../../ledger/test_helpers import testLedgerConfig

const testChainSyncProtocol* = "/logos-blockchain-testnet-v0.1.2/chainsync/1.0.0"

proc initTestChain*(genesis: Block): Chain =
  ## Chain over the genesis block's ledger state (epochs seeded under
  ## `testLedgerConfig`).
  let state = LedgerState.fromGenesis(
      genesis.txs, default(FieldElement), testSdpRegistry(),
      testLedgerConfig).valueOr:
    raiseAssert "initTestChain: " & $error
  Chain.init(
    genesis,
    Ledger[BlockId].init(blockId(genesis.header), state, testLedgerConfig,
        mockVerifyLeaderProof),
    SlotConfig(genesisTime: 0, slotDurationSeconds: 1))

proc startTestProcessor(chain: Chain): BlockProcessor =
  let bp = BlockProcessor.new(chain)
  bp.start()
  bp

proc mountTestServer*(
    sw: Switch, chain: Chain, protocol = testChainSyncProtocol
): Syncer {.raises: [LPError].} =
  ## Syncer that only serves. Its processor loop does not run.
  let syncer = Syncer.init(sw, BlockProcessor.new(chain), protocol)
  mountCryptarchiaSyncHandler(syncer)
  syncer

template withProcessor*(chain: Chain, body: untyped) =
  ## Running processor over `chain`, stopped after `body`.
  let bp {.inject.} = startTestProcessor(chain)
  try:
    body
  finally:
    await bp.stop()

template withClientSyncerOn*(sw: Switch, clientChain: Chain, body: untyped) =
  ## Client syncer on the caller's switch, stopped with its processor after `body`.
  let clientSyncer {.inject.} =
    Syncer.init(sw, startTestProcessor(clientChain), testChainSyncProtocol)
  try:
    body
  finally:
    await clientSyncer.stop()
    await clientSyncer.processor.stop()

template withClientSyncer*(clientChain: Chain, body: untyped) =
  ## One switch and a client syncer, stopped after `body`.
  let client {.inject.} = await startQuicTestSwitch()
  try:
    withClientSyncerOn(client, clientChain):
      body
  finally:
    await client.stop()

template withSyncPair*(serverChain, clientChain: Chain, body: untyped) =
  ## A serving switch and a connected client syncer, stopped after `body`.
  let server {.inject.} = await startQuicTestSwitch()
  discard mountTestServer(server, serverChain)
  try:
    withClientSyncer(clientChain):
      await client.connect(server.peerInfo.peerId, server.peerInfo.addrs, forceDial = true)
      body
  finally:
    await server.stop()

proc extendChainAfterGenesis*(
    tree: LocalTree, genesis: Block, extraBlocks: int,
): BlockId =
  ## Add ``extraBlocks`` descendants on top of ``genesis``; return the tip id.
  var parentHdr = genesis.header
  var parentId = blockId(genesis.header)
  for slot in 1 .. extraBlocks:
    let blk = childBlock(parentHdr, parentId, SlotNumber(slot.uint64), [])
    check tree.addBlockToTree(blk)
    parentHdr = blk.header
    parentId = blockId(blk.header)
  parentId

func exampleBlockId*(fill: byte): BlockId =
  var id: BlockId
  for i in 0 ..< id.len:
    id[i] = fill
  id

func exampleGetTipTipFixture*(): Tip =
  Tip(tip: exampleBlockId(0xAB'u8), slot: SlotNumber(12_345'u64),
      height: 999'u64)

proc exampleSerializedGetTipResponseTipWire*(): Opt[seq[byte]] =
  let resp = GetTipResponse(kind: gtrTip, tipData: exampleGetTipTipFixture())
  try:
    let wire = serializeGetTipResponseToSeq(resp, cryptarchiaSyncBincodeConfig)
    if wire.len == 0:
      Opt.none(seq[byte])
    else:
      Opt.some(wire)
  except BincodeError, IOError:
    fail getCurrentExceptionMsg()

proc exampleSerializedGetTipResponseFailureWire*(
    failureUtf8: string = "example: tip unavailable",
): Opt[seq[byte]] =
  let resp = GetTipResponse(kind: gtrFailure, failureMessage: failureUtf8)
  try:
    let wire = serializeGetTipResponseToSeq(resp, cryptarchiaSyncBincodeConfig)
    if wire.len == 0:
      Opt.none(seq[byte])
    else:
      Opt.some(wire)
  except BincodeError, IOError:
    fail getCurrentExceptionMsg()

func downloadBlocksRequestEqual*(a, b: DownloadBlocksRequest): bool =
  a.targetBlock == b.targetBlock and
  a.knownBlocks.localTip == b.knownBlocks.localTip and
  a.knownBlocks.latestImmutableBlock == b.knownBlocks.latestImmutableBlock and
  a.knownBlocks.additionalBlocks == b.knownBlocks.additionalBlocks

func blockDownloadWireEqual*(a, b: Block): bool =
  a.header == b.header and a.signature == b.signature and a.txs.len ==
      b.txs.len and
  (0 ..< a.txs.len).allIt(encodeSignedMantleTx(a.txs[it]) ==
      encodeSignedMantleTx(b.txs[it]))

func downloadBlocksResponseEqual*(a, b: DownloadBlocksResponse): bool =
  if a.kind != b.kind:
    return false
  case a.kind
  of dbrBlock:
    a.downloadedBlock == b.downloadedBlock
  of dbrNoMoreBlocks:
    true
  of dbrFailure:
    let
      ra = a.blocksUnavailableReason
      rb = b.blocksUnavailableReason
    if ra.kind != rb.kind:
      return false
    case ra.kind
    of burBlockNotFound:
      ra.headerId == rb.headerId
    of burStartBlockNotFound:
      true
    of burUnknown:
      ra.message == rb.message

func downloadBlocksResponsesEqual*(a, b: seq[DownloadBlocksResponse]): bool =
  a.len == b.len and
  (0 ..< a.len).allIt(downloadBlocksResponseEqual(a[it], b[it]))

proc downloadBlocksResponsesForRequest*(
    tree: LocalTree, req: DownloadBlocksRequest
): seq[DownloadBlocksResponse] =
  let sendIds = cappedDownloadPathBlockIds(tree, req)
  if sendIds.len == 0:
    return @[DownloadBlocksResponse(kind: dbrNoMoreBlocks)]
  var responses = newSeqOfCap[DownloadBlocksResponse](sendIds.len + 1)
  for i in countdown(sendIds.high, 0):
    let blk = tree.getBlock(sendIds[i]).valueOr:
      fail "block not in tree"
    let innerWire = try:
      serializeBlockToSeq(blk, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check innerWire.len > 0 and innerWire.len <= MaxBlockSize
    responses.add DownloadBlocksResponse(kind: dbrBlock,
        downloadedBlock: innerWire)
  responses.add DownloadBlocksResponse(kind: dbrNoMoreBlocks)
  responses

proc u32LengthPrefixedHex*(inner: seq[byte]): string =
  try:
    byteutils.toHex(addPrefixLengthToPayload(inner))
  except BincodeError as exc:
    fail exc.msg

{.pop.}
