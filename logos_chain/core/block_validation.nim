# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}

import std/options
import libp2p/utility

import ./local_tree
import ./types
from ./types import createBlockRoot, ExpectedBedrockVersion, MaxBlockSize
from ./mantle/primitives import MaxBlockTxs, SlotNumber
from ./mantle/tx_types import SignedMantleTx, encodeSignedMantleTx

proc txBytesLen(txs: openArray[SignedMantleTx]): int =
  for stx in txs:
    result += encodeSignedMantleTx(stx).len

proc currentWallclockSlot(): SlotNumber =
  SlotNumber(1_000_000_000'u64) # TODO: map wall clock to protocol slot

proc verifyPoL(localTree: LocalTree, header: Header): bool =
  discard localTree
  discard header # TODO: verify PoL
  true

proc verifyHeaderLeaderAuth(header: Header): bool =
  discard header # TODO: leader auth / signatures
  true

proc validateBlockHeader*(blk: Block, localTree: LocalTree): bool =
  let header = blk.header

  if header.bedrockVersion != ExpectedBedrockVersion:
    return false

  if txBytesLen(blk.txs) >= MaxBlockSize:
    return false

  if blk.txs.len >= MaxBlockTxs:
    return false

  if createBlockRoot(blk.txs) != header.blockRoot:
    return false

  let parentHeader = fetchParentHeader(localTree, header.parentBlock).valueOr:
    return false
  if header.slot <= parentHeader.slot:
    return false

  if currentWallclockSlot() < header.slot:
    return false

  if not hasBlock(localTree, header.parentBlock):
    return false

  let parentHeight = blockHeight(localTree, header.parentBlock).valueOr:
    return false
  let candidateHeight = parentHeight + 1'u64
  if candidateHeight <= localTree.latestImmutableHeight:
    return false

  if not verifyPoL(localTree, header):
    return false

  if not verifyHeaderLeaderAuth(header):
    return false

  true

proc validateBlockBody*(blk: Block): bool =
  discard blk # TODO: body checks
  true

{.pop.}
