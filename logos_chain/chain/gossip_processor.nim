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
  stew/byteutils,
  libp2p/peerid,
  libp2p/protocols/pubsub/pubsub,
  ./block_processor

logScope:
  topics = "gossip_processor"

proc processProposal*(
    bp: BlockProcessor, proposal: Proposal, src: PeerId
): ValidationResult =
  let
    id = blockId(proposal.header)
    idHex = toHex(id)

  if proposal.header.slot <= bp.localTree.latestImmutableSlot():
    debug "GossipSub ignored proposal at or behind immutable slot",
      blockId = idHex, src
    return ValidationResult.Ignore

  let nowSlot = bp.currentWallclockSlot()
  if proposal.header.slot > nowSlot:
    debug "GossipSub ignored future proposal (clock skew)",
      blockId = idHex, blockSlot = proposal.header.slot, wallclockSlot = nowSlot, src
    return ValidationResult.Ignore

  # Only accepted copies are in flight, applied or buffered.
  if bp.checkDeduplication(id, proposal.signature).isErr:
    trace "GossipSub ignored duplicate proposal", blockId = idHex, src
    return ValidationResult.Ignore

  # Header rules that need no mempool access run before any reference lookup.
  if proposal.header.bedrockVersion != ExpectedBedrockVersion:
    debug "GossipSub rejected proposal with unsupported bedrock version",
      blockId = idHex, version = proposal.header.bedrockVersion, src
    return ValidationResult.Reject
  if not verify_signature(proposal.header, proposal.signature):
    debug "GossipSub rejected proposal with invalid header signature",
      blockId = idHex, src
    return ValidationResult.Reject

  # The body root is checked inside, so a tampered copy is never queued.
  discard reconstructProposalTxs(proposal, bp.mempool).valueOr:
    case error
    of ProposalValidationError.BodyRootMismatch:
      debug "GossipSub rejected proposal: references do not match body root",
        blockId = idHex, src
      return ValidationResult.Reject
    of ProposalValidationError.MissingReference,
        ProposalValidationError.CollidingReference:
      debug "GossipSub cannot accept proposal: unresolved reference",
        blockId = idHex, error = $error, src
      return ValidationResult.Ignore

  discard bp.addProposal(proposal, id)

  debug "GossipSub accepted proposal into block queue",
    blockId = idHex, slot = proposal.header.slot, src
  ValidationResult.Accept

proc processTx*(
    bp: BlockProcessor, htx: HashedSignedMantleTx, src: PeerId
): ValidationResult =
  let txHashHex = toHex(htx.hash)

  if htx.hash in bp.mempool:
    trace "GossipSub ignored duplicate tx already in mempool",
      txHash = txHashHex, src
    return ValidationResult.Ignore

  let validTx = validateMantleTxStateless(htx).valueOr:
    debug "GossipSub rejected invalid mantle tx",
      txHash = txHashHex, error = $error, src
    return ValidationResult.Reject

  let
    nowSlot = bp.currentWallclockSlot()
    added = bp.mempool.add(validTx, nowSlot)
  if not added:
    trace "GossipSub ignored duplicate tx already in mempool",
      txHash = txHashHex, src
    return ValidationResult.Ignore

  ValidationResult.Accept

{.pop.}
