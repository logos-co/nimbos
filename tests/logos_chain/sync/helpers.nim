# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import std/[sequtils, algorithm]
import results
import bincode
import stew/byteutils as byteutils
import ../../testutil

import ../../../logos_chain/core/types
import ../../../logos_chain/chain/genesis
import ../../../logos_chain/core/local_tree
import ../../../logos_chain/sync/[framing, types, initial_block_download]

from ../../../logos_chain/core/mantle/primitives import SlotNumber
from ../../../logos_chain/core/mantle/tx_types import MantleTx, SignedMantleTx, encodeSignedMantleTx

const testChainSyncProtocol* = "/logos-blockchain-testnet-v0.1.2/chainsync/1.0.0"

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

func exampleBlockId*(fill: byte): BlockId =
  var id: BlockId
  for i in 0 ..< id.len:
    id[i] = fill
  id

func exampleGetTipTipFixture*(): Tip =
  Tip(tip: exampleBlockId(0xAB'u8), slot: SlotNumber(12_345'u64), height: 999'u64)

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
  a.header == b.header and a.txs.len == b.txs.len and
  (0 ..< a.txs.len).allIt(encodeSignedMantleTx(a.txs[it]) == encodeSignedMantleTx(b.txs[it]))

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
  a.len == b.len and
  (0 ..< a.len).allIt(downloadBlocksResponseEqual(a[it], b[it]))

proc downloadBlocksResponsesForRequest*(
    tree: LocalTree, req: DownloadBlocksRequest
): seq[DownloadBlocksResponse] =
  var blocks = collectBlocksTargetToAncestor(tree, req)
  if blocks.len == 0:
    return @[DownloadBlocksResponse(kind: dbrNoMoreBlocks)]
  reverse(blocks)
  var responses = newSeqOfCap[DownloadBlocksResponse](blocks.len + 1)
  for blk in blocks:
    let innerWire = try:
      serializeBlockToSeq(blk, cryptarchiaSyncBincodeConfig)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()
    check innerWire.len > 0 and innerWire.len <= MaxBlockSize
    responses.add DownloadBlocksResponse(kind: dbrBlock, downloadedBlock: innerWire)
  responses.add DownloadBlocksResponse(kind: dbrNoMoreBlocks)
  responses

proc u32LengthPrefixedHex*(inner: seq[byte]): string =
  try:
    byteutils.toHex(addPrefixLengthToPayload(inner))
  except BincodeError as exc:
    fail exc.msg

{.pop.}
