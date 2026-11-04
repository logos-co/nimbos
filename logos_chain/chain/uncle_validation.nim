# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Uncle validity rules, Cryptarchia "Block Header Validation" step 10.
## Spec: https://github.com/logos-co/logos-lips/blob/fddc2c1911626f7b1949360b8924bb6c05252bff/docs/blockchain/raw/cryptarchia-v1-protocol.md#uncle-references

{.push raises: [], gcsafe.}

import
  ./local_tree,
  ../ledger/ledger

from ../core/types import BlockId, MaxUncles, blockId, verify_signature, asSeq
from ../core/crypto/types import isZero
from ./block_validation import AdmittedBlock, header, uncleHeaders

type UncleError* {.pure.} = enum
  NotStrictlyOlder ## sl_U >= sl_A
  NotAfterParent ## sl_U <= sl_parent(U)
  ParentNotOnChain ## parent of U is not on the chain of A inside the window
  OnChain ## U is on the chain of A
  InvalidSignature ## σ_U does not verify over U under its leader key
  InvalidProof ## PoL of U fails against the parent state advanced to sl_U

proc validateUncles*(
    blk: AdmittedBlock,
    localTree: LocalTree,
    ledger: Ledger[BlockId],
): Result[void, UncleError] =
  ## Step 10: every carried uncle satisfies `valid_uncle` on the chain of `blk`.
  # A template, not a `let`: the list is read in place, never copied.
  template uncles: untyped = blk.uncleHeaders.asSeq
  if uncles.len == 0:
    return ok()
  let slot = blk.header.slot
  var uncleIds: array[MaxUncles, BlockId]
  for i in 0 ..< uncles.len:
    if uncles[i].header.slot >= slot:
      return err(NotStrictlyOlder)
    uncleIds[i] = blockId(uncles[i].header)

  # Walk the chain of `blk` from its parent back to the window start. The
  # window is anchored to the parent of the uncle, so the walk stops at the
  # first node older than the window. A parent not seen by then is out of
  # the window. The start saturates at slot 0 for a block younger than the
  # window.
  let
    window = ledger.config.uncleWindowSlots
    windowStart = if slot > window: slot - window else: SlotNumber(0)
  var
    parentSlots: array[MaxUncles, Opt[SlotNumber]]
    current = blk.header.parentBlock
  while true:
    # Fork pruning never removes a canonical ancestor, so a missing header
    # is a defensive stop only.
    let hdr = localTree.fetchHeader(current).valueOr:
      break
    if hdr.slot < windowStart:
      break
    for i in 0 ..< uncles.len:
      if current == uncleIds[i]:
        return err(OnChain)
      if current == uncles[i].header.parentBlock:
        parentSlots[i] = Opt.some(hdr.slot)
    if hdr.parentBlock.isZero:
      break
    current = hdr.parentBlock

  for i in 0 ..< uncles.len:
    let parentSlot = parentSlots[i].valueOr:
      return err(ParentNotOnChain)
    if uncles[i].header.slot <= parentSlot:
      return err(NotAfterParent)
  for i in 0 ..< uncles.len:
    if not verify_signature(uncles[i].header, uncles[i].signature):
      return err(InvalidSignature)

  # The proof verifies against the parent state advanced to the uncle slot,
  # which is the epoch state of that slot on the chain of `blk`. The state is
  # absent only when the window in slots reaches past the immutable block.
  # That needs W >= k * f. The spec defaults keep W/f six times below k.
  for i in 0 ..< uncles.len:
    let parentState = ledger.state(uncles[i].header.parentBlock).valueOr:
      return err(ParentNotOnChain)
    parentState.advanceAndVerifyLeader(
      uncles[i].header.slot, uncles[i].header.proofOfLeadership, ledger.config,
      ledger.leaderProofVerifier,
    ).isOkOr:
      return err(InvalidProof)
  ok()

{.pop.}
