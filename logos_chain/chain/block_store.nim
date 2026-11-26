# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/tables,
  results,
  ../core/types,
  ./block_validation

type
  # TODO: Back `BlockStore` with persistent disk storage instead of keeping all canonical
  # `ValidBlock` bodies in RAM forever.
  BlockStore* = ref object
    blocks: Table[BlockId, ValidBlock]

func init*(T: type BlockStore, genesisBlock: ValidBlock): BlockStore =
  BlockStore(blocks: [(blockId(genesisBlock.header), genesisBlock)].toTable)

proc put*(store: BlockStore, id: BlockId, blk: ValidBlock) =
  store.blocks[id] = blk

func getBlock*(store: BlockStore, id: BlockId): Opt[ValidBlock] =
  store.blocks.withValue(id, blk):
    return Opt.some(blk[])
  Opt.none(ValidBlock)

proc del*(store: BlockStore, id: BlockId) =
  store.blocks.del(id)

{.pop.}
