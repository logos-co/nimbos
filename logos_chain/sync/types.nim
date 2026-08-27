# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import
  ../core/[local_tree, types],
  bincode
export local_tree.Tip
export types

const MaxRequestBlocks* = 128
  ## Maximum blocks served per ``DownloadBlocksRequest`` (DoS limit).

type
  KnownBlocks* = object
    localTip*: BlockId
    latestImmutableBlock*: BlockId
    additionalBlocks*: seq[BlockId]

  DownloadBlocksRequest* = object
    targetBlock*: BlockId
    knownBlocks*: KnownBlocks

type
  SerializedBlock = seq[byte]
    ## Bincode-encoded ``Block`` bytes (``encode`` / ``decode``).

type
  BlocksUnavailableReasonKind* {.pure.} = enum
    burBlockNotFound = 0
    burStartBlockNotFound = 1
    burUnknown = 2

  BlocksUnavailableReason* = object
    case kind*: BlocksUnavailableReasonKind
    of burBlockNotFound:
      headerId*: BlockId
    of burStartBlockNotFound:
      discard
    of burUnknown:
      message*: string

  DownloadBlocksResponseKind* {.pure.} = enum
    dbrBlock = 0
    dbrNoMoreBlocks = 1
    dbrFailure = 2

  DownloadBlocksResponse* = object
    case kind*: DownloadBlocksResponseKind
    of dbrBlock:
      downloadedBlock*: SerializedBlock
    of dbrNoMoreBlocks:
      discard
    of dbrFailure:
      blocksUnavailableReason*: BlocksUnavailableReason

type
  RequestMessageKind* {.pure.} = enum
    rmDownloadBlocksRequest = 0
    rmGetTip = 1

  RequestMessage* = object
    case kind*: RequestMessageKind
    of rmDownloadBlocksRequest:
      downloadBlocksRequest*: DownloadBlocksRequest
    of rmGetTip:
      discard

type
  GetTipResponseKind* {.pure.} = enum
    gtrTip = 0
    gtrFailure = 1

  GetTipResponse* = object
    case kind*: GetTipResponseKind
    of gtrTip:
      tipData*: Tip
    of gtrFailure:
      failureMessage*: string

type
  IBDFailure* = object of CatchableError
  InvalidBlock* = object of CatchableError

const cryptarchiaSyncBincodeConfig* = BincodeConfig(
  byteOrder: LittleEndian,
  intSize: 8,
  sizeLimit: high(uint64),
)

deriveBincode(KnownBlocks)
deriveBincode(DownloadBlocksRequest)
deriveBincode(BlocksUnavailableReason)
deriveBincode(DownloadBlocksResponse)
deriveBincode(RequestMessage)
deriveBincode(GetTipResponse)

{.pop.}
