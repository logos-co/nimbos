# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

## Bedrock `valid_header(B)` from block construction / validation spec.
## Spec: [1.1.1 Block Construction, Validation and Execution](https://nomos-tech.notion.site/1-1-1-Block-Construction-Validation-and-Execution-269261aa09df807185a9e0764acffe22)

{.push raises: [], gcsafe.}

import results
import ./local_tree

from ./types import
  Block, Header, createBlockRoot, ExpectedBedrockVersion, MaxBlockSize
from ./mantle/primitives import MaxBlockTxs, SlotNumber
from ./mantle/tx_types import SignedMantleTx, encodeSignedMantleTx

func wallclockSlot(): SlotNumber =
  ## TODO: implement `wallclock_time().to_slot()` from deployment genesis time
  ## and slot duration.
  high(SlotNumber)

proc txBytesLen(txs: openArray[SignedMantleTx]): int =
  var total = 0
  for stx in txs:
    total += encodeSignedMantleTx(stx).len
  total

proc verifyPoL(localTree: LocalTree, header: Header): bool =
  ## TODO: implement `verifyPoL()`.
  discard localTree
  discard header
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

  if wallclockSlot() < header.slot:
    return false

  if not hasBlock(localTree, header.parentBlock):
    return false

  if not isFutureDescendantOfImmutable(localTree, header):
    return false

  if not verifyPoL(localTree, header):
    return false

  true

proc validateBlockBody*(blk: Block): bool =
  discard blk # TODO: body checks
  true

proc validateBlock*(blk: Block, localTree: LocalTree): bool =
  validateBlockHeader(blk, localTree) and validateBlockBody(blk)

{.pop.}
