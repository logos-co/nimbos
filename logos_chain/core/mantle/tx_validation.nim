# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Stateless and cryptographic transaction validation for Mantle transactions.
## Spec: [Bedrock v1.1 — Mantle Specification v1.10.0](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md)

{.push raises: [], gcsafe.}

import
  std/[sets, sequtils],
  results,
  libp2p/crypto/ed25519/ed25519,
  libp2p/multiaddress,
  ./poc_verifier,
  ./primitives,
  ./operations,
  ./proofs,
  ./tx_hashing,
  ./tx_types

type
  StatelessLedgerError* {.pure.} = enum
    ## Stateless and monotonic terminal transaction errors.
    DoubleSpend ## same NoteId appears twice as an input across the transaction
    ZeroValueNote ## output Note has value == 0
    InvalidProof ## ZK multi-sig, leader-proof, or signature verify failed
    UnsupportedOp ## Op kind not yet wired in this ledger version
    EmptyLocators ## SDP Declare locators must contain at least one element
    TooManyLocators
    InvalidLocator
    InvalidChannelConfig ## ChannelConfig has zero threshold or empty keys
    EmptyInputs ## Deposit/Withdraw/Transfer must consume at least one note
    VerifierNotInitialised ## per-circuit VK singleton wasn't installed at startup

export results, StatelessLedgerError

proc validateMantleTxStateless*(
    tx: SignedMantleTx,
    verifyProof: ProofOfClaimVerifier = verifyProofOfClaim,
): Result[void, StatelessLedgerError] =
  ## Stateless transaction validation in a single pass: structural checks
  ## (opcode support, payload consistency, proof kind matching) plus standalone
  ## cryptographic proof and signature verifications (Ed25519 signatures and PoC Groth16).
  if tx.tx.ops.len != tx.opProofs.len:
    return err(StatelessLedgerError.InvalidProof)

  var txHash: Opt[ZkHash]
  template getTxHash(): ZkHash =
    txHash.valueOr:
      let h = mantleTxHash(tx.tx)
      txHash = Opt.some(h)
      h

  var allInputs: HashSet[NoteId]

  for i in 0 ..< tx.tx.ops.len:
    let op = tx.tx.ops[i]
    let proof = tx.opProofs[i]
    if not isSupportedOpcode(op.opcode):
      return err(StatelessLedgerError.UnsupportedOp)
    if op.opcode != opPayloadToOpcode(op.payload):
      return err(StatelessLedgerError.UnsupportedOp)
    if proof.kind != expectedOpProofKindForOpcode(op.opcode):
      return err(StatelessLedgerError.InvalidProof)

    case op.payload.kind
    of Transfer:
      template t: untyped = op.payload.transfer
      if t.inputs.noteIds.len == 0:
        return err(StatelessLedgerError.EmptyInputs)
      if t.inputs.noteIds.anyIt(allInputs.containsOrIncl(it)):
        return err(StatelessLedgerError.DoubleSpend)
      if t.outputs.notes.anyIt(it.value == 0):
        return err(StatelessLedgerError.ZeroValueNote)

    of ChannelDeposit:
      template d: untyped = op.payload.channelDeposit
      if d.inputs.len == 0:
        return err(StatelessLedgerError.EmptyInputs)
      if d.inputs.anyIt(allInputs.containsOrIncl(it)):
        return err(StatelessLedgerError.DoubleSpend)

    of ChannelWithdraw:
      template w: untyped = op.payload.channelWithdraw
      if w.inputs.len == 0:
        return err(StatelessLedgerError.EmptyInputs)
      if w.inputs.anyIt(allInputs.containsOrIncl(it)):
        return err(StatelessLedgerError.DoubleSpend)

    of ChannelTransfer:
      template ct: untyped = op.payload.channelTransfer
      if ct.inputs.len == 0:
        return err(StatelessLedgerError.EmptyInputs)
      if ct.inputs.anyIt(allInputs.containsOrIncl(it)):
        return err(StatelessLedgerError.DoubleSpend)
      if ct.outputs.anyIt(it.value == 0):
        return err(StatelessLedgerError.ZeroValueNote)

    of ChannelConfig:
      template cfg: untyped = op.payload.channelConfig
      if cfg.keys.len == 0 or cfg.configurationThreshold == 0 or
          cfg.configurationThreshold.int > cfg.keys.len or
          cfg.transferThreshold == 0:
        return err(StatelessLedgerError.InvalidChannelConfig)

    of ChannelInscribe:
      if not verify(proof.ed25519SigProof, getTxHash(), op.payload.channelInscribe.signer):
        return err(StatelessLedgerError.InvalidProof)

    of SdpDeclare:
      template decl: untyped = op.payload.sdpDeclare
      if decl.locators.len == 0:
        return err(StatelessLedgerError.EmptyLocators)
      if decl.locators.len > MaxSdpLocators:
        return err(StatelessLedgerError.TooManyLocators)
      if decl.locators.anyIt(not isValidLocator(it)):
        return err(StatelessLedgerError.InvalidLocator)
      if not verify(proof.declarationProof.ed25519Sig, getTxHash(), decl.providerId):
        return err(StatelessLedgerError.InvalidProof)

    of SdpWithdraw, SdpActive:
      discard # No stateless-only invariants for SdpWithdraw / SdpActive

    of LeaderClaim:
      if verifyProof == nil:
        return err(StatelessLedgerError.VerifierNotInitialised)
      template claim: untyped = op.payload.leaderClaim
      let public = proofOfClaimPublic(claim, claim.rewardsRoot, getTxHash())
      let verified = verifyProof(proof.proofOfClaimProof, public).valueOr:
        return err(StatelessLedgerError.VerifierNotInitialised)
      if not verified:
        return err(StatelessLedgerError.InvalidProof)

  ok()

{.pop.}
