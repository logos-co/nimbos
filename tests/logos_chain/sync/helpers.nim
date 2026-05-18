# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [].}

import std/options
import stew/byteutils as byteutils
import unittest2

import "../../../logos_chain/bedrock/block"/[block_types, genesis]
import "../../../logos_chain/bedrock/mantle/tx_types"
import "../../../logos_chain/bedrock/local_tree"
import "../../../logos_chain/sync"/[config, types, initial_block_download]

from "../../../logos_chain/bedrock/mantle/primitives" import SlotNumber
from "../../../logos_chain/bedrock/mantle/tx_encoding" import encodeSignedMantleTx

const testChainSyncProtocol* = "/logos-blockchain-testnet-v0.1.2/chainsync/1.0.0"
  ## Matches ``network.chain_sync_protocol_name`` in ``config/deployment-settings.yaml``.

proc minimalSignedTx*(): SignedMantleTx =
  SignedMantleTx(
    tx: MantleTx(
      ops: @[],
      executionGasPrice: 0'u64,
      permanentStorageGasPrice: 0'u64,
    ),
    opProofs: @[],
  )

proc childBlock*(
    parentHdr: Header, parentId: BlockId, slot: SlotNumber, txs: openArray[SignedMantleTx]
): Block =
  let h = initHeader(
    bedrockVersion = parentHdr.bedrockVersion,
    parentBlock = parentId,
    slot = slot,
    txs = txs,
    proofOfLeadership = parentHdr.proofOfLeadership,
  )
  initBlock(h, txs)

func exampleBlockId*(fill: byte): BlockId {.raises: [].} =
  var id: BlockId
  for i in 0 ..< id.len:
    id[i] = fill
  id

func exampleGetTipTipFixture*(): Tip {.raises: [].} =
  Tip(tip: exampleBlockId(0xAB'u8), slot: SlotNumber(12_345'u64), height: 999'u64)

proc exampleSerializedGetTipResponseTipWire*(): Option[seq[byte]] {.raises: [].} =
  let resp = GetTipResponse(kind: gtrTip, tipData: exampleGetTipTipFixture())
  try:
    let wire = serializeGetTipResponseToSeq(resp, cryptarchiaSyncBincodeConfig)
    if wire.len == 0:
      none(seq[byte])
    else:
      some(wire)
  except CatchableError:
    none(seq[byte])

proc exampleSerializedGetTipResponseFailureWire*(
    failureUtf8: string = "example: tip unavailable",
): Option[seq[byte]] {.raises: [].} =
  let resp = GetTipResponse(kind: gtrFailure, failureMessage: failureUtf8)
  try:
    let wire = serializeGetTipResponseToSeq(resp, cryptarchiaSyncBincodeConfig)
    if wire.len == 0:
      none(seq[byte])
    else:
      some(wire)
  except CatchableError:
    none(seq[byte])

func downloadBlocksRequestEqual*(a, b: DownloadBlocksRequest): bool =
  a.targetBlock == b.targetBlock and
  a.knownBlocks.localTip == b.knownBlocks.localTip and
  a.knownBlocks.latestImmutableBlock == b.knownBlocks.latestImmutableBlock and
  a.knownBlocks.additionalBlocks == b.knownBlocks.additionalBlocks

func blockDownloadWireEqual*(a, b: Block): bool =
  if a.header != b.header or a.txs.len != b.txs.len:
    return false
  for i in 0 ..< a.txs.len:
    if encodeSignedMantleTx(a.txs[i]) != encodeSignedMantleTx(b.txs[i]):
      return false
  true

func downloadBlocksResponseEqual*(a, b: DownloadBlocksResponse): bool =
  if a.kind != b.kind:
    return false
  case a.kind
  of dbrBlock:
    a.downloadedBlock == b.downloadedBlock
  of dbrNoMoreBlocks:
    true
  of dbrFailure:
    if a.failureReason.kind != b.failureReason.kind:
      return false
    case a.failureReason.kind
    of burBlockNotFound:
      b.failureReason.kind == burBlockNotFound and
        a.failureReason.blockNotFoundId == b.failureReason.blockNotFoundId
    of burStartBlockNotFound:
      true
    of burUnknown:
      b.failureReason.kind == burUnknown and
        a.failureReason.unknownMessage == b.failureReason.unknownMessage

func downloadBlocksResponsesEqual*(a, b: seq[DownloadBlocksResponse]): bool =
  if a.len != b.len:
    return false
  for i in 0 ..< a.len:
    if not downloadBlocksResponseEqual(a[i], b[i]):
      return false
  true

proc downloadBlocksResponsesForRequest*(
    tree: LocalTree, req: DownloadBlocksRequest
): seq[DownloadBlocksResponse] =
  let blocks = collectBlocksForDownloadRequest(tree, req)
  if blocks.len == 0:
    return @[DownloadBlocksResponse(kind: dbrNoMoreBlocks)]
  result = newSeqOfCap[DownloadBlocksResponse](blocks.len + 1)
  for blk in blocks:
    let innerWire = try:
      serializeBlockToSeq(blk, cryptarchiaSyncBincodeConfig)
    except CatchableError:
      @[]
    check innerWire.len > 0 and innerWire.len <= MaxBlockSize
    result.add DownloadBlocksResponse(kind: dbrBlock, downloadedBlock: innerWire)
  result.add DownloadBlocksResponse(kind: dbrNoMoreBlocks)

proc lpPrefixedHex*(inner: seq[byte]): string {.raises: [].} =
  try:
    byteutils.toHex(addPrefixLengthToPayload(inner))
  except CatchableError:
    ""

{.pop.}
