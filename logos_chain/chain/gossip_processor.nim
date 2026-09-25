# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## GossipSub message validation and processor ingestion for proposals and transactions.

{.push raises: [], gcsafe.}

import
  chronicles,
  results,
  stew/byteutils,
  libp2p/peerid,
  libp2p/protocols/pubsub/pubsub,
  ./block_processor,
  ./proposal,
  ../core/types,
  ../core/mantle/[tx_hashing, tx_types, tx_validation]

logScope:
  topics = "gossip_processor"

proc processProposal*(
    bp: BlockProcessor, proposal: Proposal, src: PeerId
): ValidationResult =
  let id = blockId(proposal.header)
  let idHex = toHex(id)

  if bp.localTree.hasBlock(id):
    trace "GossipSub ignored already applied proposal", blockId = idHex, src
    return ValidationResult.Ignore

  let nowSlot = bp.currentWallclockSlot()
  if proposal.header.slot > nowSlot:
    debug "GossipSub ignored future proposal (clock skew)",
      blockId = idHex, blockSlot = proposal.header.slot, wallclockSlot = nowSlot, src
    return ValidationResult.Ignore

  if proposal.header.slot <= bp.localTree.latestImmutableSlot():
    debug "GossipSub ignored proposal at or behind immutable slot",
      blockId = idHex, src
    return ValidationResult.Ignore

  if not bp.localTree.hasBlock(proposal.header.parentBlock):
    debug "GossipSub ignored proposal with unknown parent",
      blockId = idHex, parent = toHex(proposal.header.parentBlock), src
    return ValidationResult.Ignore

  let blk = reconstructBlock(proposal, bp.mempool).valueOr:
    debug "GossipSub cannot reconstruct block from proposal: missing tx in mempool",
      blockId = idHex, error = $error, src
    return ValidationResult.Ignore

  discard bp.addBlock(BlockSource.Gossip, blk)

  debug "GossipSub accepted reconstructed block into local tree",
    blockId = idHex, slot = blk.header.slot, src
  ValidationResult.Accept

proc processTx*(
    bp: BlockProcessor, tx: SignedMantleTx, src: PeerId
): ValidationResult =
  # Reject malformed payloads before hashing:
  # 1. Enforces OpCount byte bounds (0 < ops.len <= 255) to prevent doAssert failure in encodeOps during mantleTxHash.
  # 2. Ensures operations and opProofs counts match with zero allocations before running crypto verifications.
  if tx.tx.ops.len == 0 or tx.tx.ops.len > int(high(uint8)) or tx.tx.ops.len != tx.opProofs.len:
    debug "GossipSub rejected malformed tx (invalid op bounds or proof mismatch)",
      opCount = tx.tx.ops.len, proofCount = tx.opProofs.len, src
    return ValidationResult.Reject

  let txHash = mantleTxHash(tx.tx).valueOr:
    debug "GossipSub rejected malformed tx (hashing failed)",
      error = $error, src
    return ValidationResult.Reject
  let txHashHex = toHex(txHash)

  if txHash in bp.mempool:
    trace "GossipSub ignored duplicate tx already in mempool",
      txHash = txHashHex, src
    return ValidationResult.Ignore

  if validateMantleTxStateless(tx).isErr:
    debug "GossipSub rejected invalid mantle tx",
      txHash = txHashHex, src
    return ValidationResult.Reject

  let nowSlot = bp.currentWallclockSlot()
  let added = bp.mempool.add(ValidSignedMantleTx(tx), nowSlot).valueOr:
    debug "GossipSub rejected tx (mempool add failed)",
      error = $error, src
    return ValidationResult.Reject
  if not added:
    trace "GossipSub ignored duplicate tx already in mempool",
      txHash = txHashHex, src
    return ValidationResult.Ignore

  ValidationResult.Accept

{.pop.}
