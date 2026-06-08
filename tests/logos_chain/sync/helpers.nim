# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [].}

import results
import bincode
import stew/byteutils as byteutils
import ../../testutil

import ../../../logos_chain/core/types
import ../../../logos_chain/chain/genesis
import ../../../logos_chain/core/local_tree
import ../../../logos_chain/sync/[config, types, initial_block_download]

from ../../../logos_chain/core/mantle/primitives import SlotNumber
from ../../../logos_chain/core/mantle/tx_types import MantleTx, SignedMantleTx, encodeSignedMantleTx

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

proc exampleSerializedGetTipResponseTipWire*(): Opt[seq[byte]] {.raises: [].} =
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
): Opt[seq[byte]] {.raises: [].} =
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
    a.failureMessage == b.failureMessage

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
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check innerWire.len > 0 and innerWire.len <= MaxBlockSize
    result.add DownloadBlocksResponse(kind: dbrBlock, downloadedBlock: innerWire)
  result.add DownloadBlocksResponse(kind: dbrNoMoreBlocks)

proc u32LengthPrefixedHex*(inner: seq[byte]): string {.raises: [].} =
  try:
    byteutils.toHex(addPrefixLengthToPayload(inner))
  except BincodeError as exc:
    fail exc.msg

{.pop.}
