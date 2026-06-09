# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import ../core/local_tree
import ../core/mantle/tx_bincode
import bincode
import libp2p/crypto/ed25519/ed25519

from ../core/types import Block, BlockId, Header, ProofOfLeadership

export local_tree.Tip
export tx_bincode

# ---------------------------------------------------------------------------
# IBD download request
# ---------------------------------------------------------------------------

type
  KnownBlocks* = object
    localTip*: BlockId
    latestImmutableBlock*: BlockId
    additionalBlocks*: seq[BlockId]

  DownloadBlocksRequest* = object
    targetBlock*: BlockId
    knownBlocks*: KnownBlocks

# ---------------------------------------------------------------------------
# IBD download response
# ---------------------------------------------------------------------------

type
  SerializedBlock = seq[byte]
    ## Bincode-encoded ``Block`` bytes (``serializeBlockToSeq`` / ``deserializeBlock``).

type
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
      failureMessage*: string

# ---------------------------------------------------------------------------
# Chain-sync request envelope
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# GetTip response
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# IBD client
# ---------------------------------------------------------------------------

type
  IBDFailure* = object of CatchableError
  InvalidBlock* = object of CatchableError

# ---------------------------------------------------------------------------
# Bincode derives (wire codecs)
# ---------------------------------------------------------------------------

const cryptarchiaSyncBincodeConfig* = BincodeConfig(
  byteOrder: LittleEndian,
  intSize: 8,
  sizeLimit: high(uint64),
)

deriveBincode(EdPublicKey)
deriveBincode(EdSignature)
deriveBincode(ProofOfLeadership)
deriveBincode(Header)
deriveBincode(Block)

deriveBincode(Tip)
deriveBincode(KnownBlocks)
deriveBincode(DownloadBlocksRequest)
deriveBincode(DownloadBlocksResponse)
deriveBincode(RequestMessage)
deriveBincode(GetTipResponse)

{.pop.}
