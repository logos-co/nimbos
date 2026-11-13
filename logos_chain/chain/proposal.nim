# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

## Bedrock block proposal construction and transaction selection.
## Spec: [Block Construction, Validation and Execution v1.3.0](https://github.com/logos-co/logos-lips/blob/4deef612ce1ae1776167daf8779d4abae953201b/docs/blockchain/raw/bedrock-v1.1-block-construction.md)
## Spec: [Execution Market v1.1.0](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/execution-market.md)

{.push raises: [], gcsafe.}

import
  std/[sequtils, tables],
  chronicles,
  libp2p/crypto/ed25519/ed25519,
  ../core/types,
  ../ledger/ledger,
  ../mempool

const
  TxMaturitySlots* = 3'u64
  MaxConsecutiveCandidateMisses = 10

proc selectProposalReferences*(
    m: Mempool,
    tipLedgerState: LedgerState,
    cfg: LedgerConfig,
    currentSlot: SlotNumber,
    verifyPoq: ProofOfQuotaVerifier = verifyProofOfQuota,
    maxTxs: int = MaxBlockTxs,
    maxBytes: int = MaxBlockSize,
): seq[Hash32] =
  ## Selects the hashes to reference, in block order, within the count,
  ## execution-gas and byte budgets.
  ## Spec: [Execution Market — Block Construction](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/execution-market.md#block-builder-mechanism-block-construction)
  var
    refs = newSeqOfCap[Hash32](maxTxs)
    workingLedger = tipLedgerState.advanceEpochAndMarket(currentSlot, cfg).valueOr:
      tipLedgerState
    cumulativeExecutionGas = Gas(0)
    cumulativeBytes = 0
    consecutiveMisses = 0
    toEvict: seq[Hash32]

  let epoch = workingLedger.epochs.activeEpoch.epoch

  for hash in m.queue:
    if refs.len >= maxTxs:
      break

    m.txs.withValue(hash, item):
      if currentSlot < item.addedAtSlot + TxMaturitySlots:
        # Immature transactions are skipped without counting toward consecutive candidate misses
        continue

      # Lazily compute and cache byteSize and execGas on first evaluation
      let
        txBytes = item.byteSize.valueOr:
          let sz = byteLen(item.tx)
          item.byteSize = Opt.some(sz)
          sz
        execGas = item.execGas.valueOr:
          let eg = txExecutionGas(item.tx).valueOr:
            continue
          item.execGas = Opt.some(eg)
          eg
        nextExecutionGas = cumulativeExecutionGas.checkedAdd(execGas).valueOr:
          continue

      if cumulativeBytes + txBytes > maxBytes or
          nextExecutionGas > MAX_EXECUTION_GAS_PER_BLOCK:
        inc consecutiveMisses
        if consecutiveMisses >= MaxConsecutiveCandidateMisses:
          break
        continue

      let (totalCost, _, _) = workingLedger.mandatory_fees(execGas, txBytes).valueOr:
        continue

      var candidate = workingLedger
      let balance = candidate.tryApplyTx(item.tx, epoch, currentSlot, verifyPoq).valueOr:
        if error == LedgerError.PermanentInvalidTxProof:
          toEvict.add(hash)
        continue

      if balance.covers(totalCost):
        refs.add(hash)
        cumulativeExecutionGas = nextExecutionGas
        cumulativeBytes += txBytes
        workingLedger = move(candidate)
        consecutiveMisses = 0

  for h in toEvict:
    warn "Evicting transaction with invalid cryptographic proof from mempool",
        txHash = h
    m.remove(h, moveToGrace = false)

  refs

proc constructProposal*(
    m: Mempool,
    tipLedgerState: LedgerState,
    cfg: LedgerConfig,
    currentSlot: SlotNumber,
    parentBlock: BlockId,
    proofOfLeadership: ProofOfLeadership,
    leaderSecKey: EdPrivateKey,
    verifyPoq: ProofOfQuotaVerifier = verifyProofOfQuota,
): Proposal =
  ## Full constructor from mempool: selects fee-paying transaction references from the
  ## mempool according to the execution market spec, constructs the header,
  ## signs it with the leader's private key, and produces the Proposal.
  # No uncle selection yet; the list stays empty.
  let
    hashes = m.selectProposalReferences(
      tipLedgerState, cfg, currentSlot, verifyPoq)
    h = initHeader(
      bedrockVersion = ExpectedBedrockVersion,
      parentBlock = parentBlock,
      slot = currentSlot,
      uncleHeaders = [],
      txHashes = hashes,
      proofOfLeadership = proofOfLeadership,
    )
    sig = signHeader(leaderSecKey, h)
  initProposal(h, [], hashes.mapIt(txReference(it)), sig)

{.pop.}
