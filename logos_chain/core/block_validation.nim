# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

## Stateless structural checks of Bedrock `valid_header(B)`. The stateful
## half (parent linkage, slot ordering, wallclock bound, leader proof) is
## owned by the `Chain.tryApplyBlock` composition: ledger `prepareUpdate`
## plus `LocalTree.addBlockToTree`.
## Spec: [Block Construction, Validation and Execution v1.1.2](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-block-construction.md)

{.push raises: [], gcsafe.}

from ./types import
  Block, createBlockRoot, ExpectedBedrockVersion, MaxBlockSize, header
from ./mantle/primitives import MaxBlockTxs
from ./mantle/tx_types import SignedMantleTx, encodeSignedMantleTx

func txBytesLen(txs: openArray[SignedMantleTx]): int =
  ## The block body is the serialized transactions only; neither the header
  ## nor the block signature counts toward `MaxBlockSize`.
  var total = 0
  for stx in txs:
    total += encodeSignedMantleTx(stx).len
  total

func validateBlockHeader(blk: Block): bool =
  if header(blk).bedrockVersion != ExpectedBedrockVersion:
    return false

  # Both bounds are inclusive: a block sitting exactly on the limit is valid.
  if txBytesLen(blk.txs) > MaxBlockSize:
    return false

  if blk.txs.len > MaxBlockTxs:
    return false

  if createBlockRoot(blk.txs) != header(blk).blockRoot:
    return false

  true

func validateBlockBody(blk: Block): bool =
  discard blk # TODO: body checks (header signature)
  true

func validateBlock*(blk: Block): bool =
  validateBlockHeader(blk) and validateBlockBody(blk)

{.pop.}
