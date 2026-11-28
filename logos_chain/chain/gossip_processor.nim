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

  # 1. Scalar slot checks (~2-20 ns)
  if proposal.header.slot <= bp.consensus.latestImmutable.slot:
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

  # A header that breaks these rules is invalid for each node, on any parent,
  # so the check runs before the topology check. `admitProposal` does the
  # check again, so that each admitted block has it.
  if not headerRulesHold(proposal.header):
    debug "GossipSub rejected proposal: invalid header", blockId = idHex, src
    return ValidationResult.Reject

  if bp.orphanPool.isRejected(id):
    debug "GossipSub ignored proposal: block was rejected",
      blockId = idHex, src
    return ValidationResult.Ignore

  if bp.orphanPool.isRejected(proposal.header.parentBlock):
    bp.orphanPool.reject(id)
    debug "GossipSub ignored proposal: parent was rejected",
      blockId = idHex, src
    return ValidationResult.Ignore

  # The topology check runs before admission, so a proposal that cannot be
  # applied costs no signature check.
  checkTopology(proposal.header, bp.consensus, bp.ledger).isOkOr:
    # A slot not after the parent slot is invalid for each node. An unviable
    # fork depends on the local view.
    if error.kind == BlockApplyErrorKind.InvalidStructure:
      debug "GossipSub rejected proposal: slot not after the parent slot",
        blockId = idHex, src
      return ValidationResult.Reject
    debug "GossipSub ignored proposal on an unviable fork", blockId = idHex, src
    return ValidationResult.Ignore

  # The checks that need no chain state run here, so the verdict covers all
  # of them and apply does not read the mempool again.
  let admittedBlk = admitProposal(proposal, bp.mempool).valueOr:
    case error
    of ProposalValidationError.UnresolvedReference:
      debug "GossipSub cannot accept proposal: unresolved reference",
        blockId = idHex, src
      return ValidationResult.Ignore
    # A body root mismatch is a Reject: the lists are not signed, and a
    # missing transaction is an Ignore through `UnresolvedReference`. An
    # Ignore here lets a peer send changed copies at no cost. A prefix
    # collision can also fail here; the spec calls it infeasible.
    of ProposalValidationError.InvalidHeader,
        ProposalValidationError.InvalidSignature,
        ProposalValidationError.BodyRootMismatch,
        ProposalValidationError.InvalidStructure:
      debug "GossipSub rejected proposal",
        blockId = idHex, error = $error, src
      return ValidationResult.Reject

  discard bp.addProposalBlock(admittedBlk, id)

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
