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
    InvalidProof ## ZK multi-sig, transfer, or signature verify failed
    UnsupportedOp ## Op kind not yet wired in this ledger version
    EmptyLocators ## SDP Declare locators must contain at least one element
    TooManyLocators
    InvalidLocator
    InvalidChannelConfig ## ChannelConfig has zero threshold or empty keys
    EmptyInputs ## Deposit/Withdraw/Transfer must consume at least one note
    VerifierNotInitialised ## per-circuit VK singleton wasn't installed at startup
    GenesisShape ## ops are not Transfer, ChannelInscribe, then SdpDeclare*
    GenesisInscription ## the parameter inscription is not on the null channel from the null key
    GenesisInputs ## the genesis Transfer consumes notes
    TooManyOps ## more ops than the u8 wire count holds
    TooManyOutputs ## more outputs than the u8 wire count holds

export results, StatelessLedgerError

func hasHeavyZkProof*(tx: SignedMantleTx): bool {.inline.} =
  tx.opProofs.anyIt(it.kind == opfLeaderClaim)

func assert_valid_output(notes: openArray[Note]): Result[void, StatelessLedgerError] =
  ## Output Notes Validation: every value is non-zero.
  if notes.anyIt(it.value == 0):
    return err(StatelessLedgerError.ZeroValueNote)
  ok()

func validateLocators(decl: DeclarationMessage): Result[void, StatelessLedgerError] =
  ## 1 to `MaxSdpLocators` entries, each a valid locator.
  if decl.locators.len == 0:
    return err(StatelessLedgerError.EmptyLocators)
  if decl.locators.len > MaxSdpLocators:
    return err(StatelessLedgerError.TooManyLocators)
  if decl.locators.anyIt(not isValidLocator(it)):
    return err(StatelessLedgerError.InvalidLocator)
  ok()

proc validateMantleTxStateless*(
    tx: SignedMantleTx,
    verifyProof: ProofOfClaimVerifier = verifyProofOfClaim,
): Result[void, StatelessLedgerError] =
  ## Stateless transaction validation staged strictly by ascending cost:
  ## Phase 1: Structural, bounds, and payload shape checks (~10 ns)
  ## Phase 2: Lazy txHash calculation & Ed25519 signature checks (~0.7 ms)
  ## Phase 3: Groth16 zk-SNARK proof verification (~1.13 ms)
  if tx.tx.ops.len != tx.opProofs.len:
    return err(StatelessLedgerError.InvalidProof)

  var allInputs: HashSet[NoteId]
  var hasSigCrypto = false
  var hasHeavyZk = false

  template checkInputs(inputs: openArray[NoteId]): untyped =
    if inputs.len == 0:
      return err(StatelessLedgerError.EmptyInputs)
    if inputs.anyIt(allInputs.containsOrIncl(it)):
      return err(StatelessLedgerError.DoubleSpend)

  # Phase 1: Structural, bounds, and payload shape checks
  for i in 0 ..< tx.tx.ops.len:
    template op: untyped = tx.tx.ops[i]
    template proof: untyped = tx.opProofs[i]

    if not isSupportedOpcode(op.opcode) or op.opcode != opPayloadToOpcode(op.payload):
      return err(StatelessLedgerError.UnsupportedOp)
    if proof.kind != expectedOpProofKindForOpcode(op.opcode):
      return err(StatelessLedgerError.InvalidProof)

    case op.payload.kind
    of Transfer:
      template t: untyped = op.payload.transfer
      checkInputs(t.inputs.noteIds)
      ?assert_valid_output(t.outputs.notes)

    of ChannelDeposit:
      checkInputs(op.payload.channelDeposit.inputs)

    of ChannelWithdraw:
      checkInputs(op.payload.channelWithdraw.inputs)

    of ChannelTransfer:
      template ct: untyped = op.payload.channelTransfer
      checkInputs(ct.inputs)
      ?assert_valid_output(ct.outputs)

    of ChannelConfig:
      template cfg: untyped = op.payload.channelConfig
      if cfg.keys.len == 0 or
          cfg.configurationThreshold == 0 or
          cfg.configurationThreshold.int > cfg.keys.len or
          cfg.transferThreshold == 0:
        return err(StatelessLedgerError.InvalidChannelConfig)

    of ChannelInscribe:
      hasSigCrypto = true

    of SdpDeclare:
      ?validateLocators(op.payload.sdpDeclare)
      hasSigCrypto = true

    of SdpWithdraw, SdpActive:
      discard # No stateless-only invariants for SdpWithdraw / SdpActive

    of LeaderClaim:
      hasHeavyZk = true

  if not hasSigCrypto and not hasHeavyZk:
    return ok()

  # Phase 2: Fast symmetric hashing & Ed25519 signatures
  var txHash: Opt[ZkHash]
  template getTxHash(): ZkHash =
    txHash.valueOr:
      let h = mantleTxHash(tx.tx)
      txHash = Opt.some(h)
      h

  if hasSigCrypto:
    for i in 0 ..< tx.tx.ops.len:
      template op: untyped = tx.tx.ops[i]
      template proof: untyped = tx.opProofs[i]
      case op.payload.kind
      of ChannelInscribe:
        if not verify(proof.ed25519SigProof, getTxHash(), op.payload.channelInscribe.signer):
          return err(StatelessLedgerError.InvalidProof)
      of SdpDeclare:
        if not verify(proof.declarationProof.ed25519Sig, getTxHash(), op.payload.sdpDeclare.providerId):
          return err(StatelessLedgerError.InvalidProof)
      else:
        discard

  if not hasHeavyZk:
    return ok()

  # Phase 3: Heavy Groth16 ZK proof verifications
  if verifyProof == nil:
    return err(StatelessLedgerError.VerifierNotInitialised)

  for i in 0 ..< tx.tx.ops.len:
    template op: untyped = tx.tx.ops[i]
    template proof: untyped = tx.opProofs[i]
    if op.payload.kind == LeaderClaim:
      template claim: untyped = op.payload.leaderClaim
      let public = proofOfClaimPublic(claim, claim.rewardsRoot, getTxHash())
      let verified = verifyProof(proof.proofOfClaimProof, public).valueOr:
        return err(StatelessLedgerError.VerifierNotInitialised)
      if not verified:
        return err(StatelessLedgerError.InvalidProof)

  ok()

func validateGenesisTxStateless*(
    tx: SignedMantleTx): Result[ValidGenesisMantleTx, StatelessLedgerError] =
  ## Every stateless genesis check: shape, wire bounds, proof kinds, the
  ## inscription envelope, inputs, outputs and locators. No proof is verified.
  template ops: untyped = tx.tx.ops
  if ops.len < 2 or ops[0].payload.kind != Transfer or
      ops[1].payload.kind != ChannelInscribe or
      not ops.toOpenArray(2, ops.high).allIt(it.payload.kind == SdpDeclare):
    return err(StatelessLedgerError.GenesisShape)
  if ops.len > MantleMaxOps:
    return err(StatelessLedgerError.TooManyOps)
  template inscribe: untyped = ops[1].payload.channelInscribe
  if inscribe.channelId != static(default(ChannelId)) or
      inscribe.signer != DefaultEd25519PublicKey:
    return err(StatelessLedgerError.GenesisInscription)
  if tx.opProofs.len != ops.len:
    return err(StatelessLedgerError.InvalidProof)
  for i in 0 ..< ops.len:
    template op: untyped = ops[i]
    if not isSupportedOpcode(op.opcode) or op.opcode != opPayloadToOpcode(op.payload):
      return err(StatelessLedgerError.UnsupportedOp)
    if tx.opProofs[i].kind != expectedOpProofKindForOpcode(op.opcode):
      return err(StatelessLedgerError.InvalidProof)
  template transfer: untyped = ops[0].payload.transfer
  if transfer.inputs.noteIds.len > 0:
    return err(StatelessLedgerError.GenesisInputs)
  if transfer.outputs.notes.len > int(high(byte)):
    return err(StatelessLedgerError.TooManyOutputs)
  ?assert_valid_output(transfer.outputs.notes)
  for op in ops.toOpenArray(2, ops.high):
    ?validateLocators(op.payload.sdpDeclare)
  ok(ValidGenesisMantleTx(tx))

{.pop.}
