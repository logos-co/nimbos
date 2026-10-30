# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Stateless and cryptographic transaction validation for Mantle transactions.
## Spec: [Bedrock v1.1 — Mantle Specification v1.17.0](https://github.com/logos-co/logos-lips/blob/949faa9563027de366514247a2a62b0de2f8c45f/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md)

{.push raises: [], gcsafe.}

import
  std/[sets, sequtils],
  libp2p/crypto/ed25519/ed25519,
  ./poc_verifier,
  ./primitives,
  ./operations,
  ./proofs,
  ./[tx_types, tx_hashing, tx_structural_validation]

export tx_structural_validation

type
  ValidSignedMantleTx* = object
    htx: HashedSignedMantleTx
    ## A ``SignedMantleTx`` that has successfully passed all stateless structural
    ## and cryptographic verifications via ``validateMantleTxStateless``.

  ValidGenesisMantleTx* = distinct ValidSignedMantleTx
    ## A ``ValidSignedMantleTx`` that passed every stateless genesis check in
    ## ``validateGenesisTxStateless``; only state checks remain.

  AnyHashedSignedMantleTx* =
    HashedSignedMantleTx | ValidSignedMantleTx | ValidGenesisMantleTx

export results

func hashed*(vtx: ValidSignedMantleTx): HashedSignedMantleTx {.inline.} =
  vtx.htx

template hashed*(gtx: ValidGenesisMantleTx): HashedSignedMantleTx =
  ValidSignedMantleTx(gtx).htx

template hash*(t: ValidSignedMantleTx | ValidGenesisMantleTx): Hash32 =
  hashed(t).hash

template tx*(t: ValidSignedMantleTx | ValidGenesisMantleTx): untyped = hashed(t).tx
template opProofs*(t: ValidSignedMantleTx | ValidGenesisMantleTx): untyped = hashed(t).opProofs

template byteLen*(t: ValidSignedMantleTx | ValidGenesisMantleTx): int =
  byteLen(hashed(t))

func hasHeavyZkProof*(tx: SignedMantleTx): bool {.inline.} =
  tx.opProofs.anyIt(it.kind == opfLeaderClaim)

proc validateMantleTxStateless*(
    htx: HashedSignedMantleTx,
    verifyProof: ProofOfClaimVerifier = verifyProofOfClaim,
): Result[ValidSignedMantleTx, StatelessLedgerError] =
  ## Stateless transaction validation staged strictly by ascending cost:
  ## Phase 1: Structural, bounds, and payload shape checks (~10 ns)
  ## Phase 2: Ed25519 signature checks (~0.7 ms)
  ## Phase 3: Groth16 zk-SNARK proof verification (~1.13 ms)
  template stx: untyped = htx.signedTx
  template txHash: untyped = htx.hash

  if stx.tx.ops.len > MantleMaxOps:
    return err(StatelessLedgerError.TooManyOps)
  if stx.tx.ops.len != stx.opProofs.len:
    return err(StatelessLedgerError.InvalidProof)

  var
    allInputs: HashSet[NoteId]
    hasSigCrypto = false
    hasHeavyZk = false

  template checkInputs(inputs: Inputs): untyped =
    if inputs.noteIds.len == 0:
      return err(StatelessLedgerError.EmptyInputs)
    if inputs.noteIds.anyIt(allInputs.containsOrIncl(it)):
      return err(StatelessLedgerError.DoubleSpend)

  # Phase 1: Structural, bounds, and payload shape checks
  for i in 0 ..< stx.tx.ops.len:
    template op: untyped = stx.tx.ops[i]
    template proof: untyped = stx.opProofs[i]

    ?checkOpShape(op, proof)

    case op.payload.kind
    of Transfer:
      template t: untyped = op.payload.transfer
      checkInputs(t.inputs)
      ?assert_valid_output(t.outputs.notes)

    of ChannelDeposit:
      # Mantle 1.17.0 bounds the deposit metadata in "Validate", before any
      # proof check. A deposit has no proof branch here, so an oversized
      # deposit would otherwise pass this function.
      template cd: untyped = op.payload.channelDeposit
      ?checkOperationData(cd.metadata)
      checkInputs(cd.inputs)

    of ChannelWithdraw:
      checkInputs(op.payload.channelWithdraw.inputs)

    of ChannelTransfer:
      template ct: untyped = op.payload.channelTransfer
      checkInputs(ct.inputs)
      ?assert_valid_output(ct.outputs.notes)

    of ChannelConfig:
      template cfg: untyped = op.payload.channelConfig
      if cfg.keys.len == 0 or
          cfg.configurationThreshold == 0 or
          cfg.configurationThreshold.int > cfg.keys.len or
          cfg.transferThreshold == 0:
        return err(StatelessLedgerError.InvalidChannelConfig)

    of ChannelInscribe:
      ?checkOperationData(op.payload.channelInscribe.inscription)
      hasSigCrypto = true

    of SdpDeclare:
      ?validateLocators(op.payload.sdpDeclare)
      hasSigCrypto = true

    of SdpWithdraw, SdpActive:
      discard # No stateless-only invariants for SdpWithdraw / SdpActive

    of LeaderClaim:
      hasHeavyZk = true

  # Phase 2: Ed25519 signatures
  if hasSigCrypto:
    for i in 0 ..< stx.tx.ops.len:
      template op: untyped = stx.tx.ops[i]
      template proof: untyped = stx.opProofs[i]
      case op.payload.kind
      of ChannelInscribe:
        if not verify(proof.ed25519SigProof, txHash, op.payload.channelInscribe.signer):
          return err(StatelessLedgerError.InvalidProof)
      of SdpDeclare:
        if not verify(proof.declarationProof.ed25519Sig, txHash, op.payload.sdpDeclare.providerId):
          return err(StatelessLedgerError.InvalidProof)
      else:
        discard

  # Phase 3: Heavy Groth16 ZK proof verifications
  if hasHeavyZk:
    if verifyProof == nil:
      return err(StatelessLedgerError.VerifierNotInitialised)

    for i in 0 ..< stx.tx.ops.len:
      template op: untyped = stx.tx.ops[i]
      template proof: untyped = stx.opProofs[i]
      if op.payload.kind == LeaderClaim:
        template claim: untyped = op.payload.leaderClaim
        let
          public = proofOfClaimPublic(claim, claim.rewardsRoot, txHash)
          verified = verifyProof(proof.proofOfClaimProof, public).valueOr:
            return err(StatelessLedgerError.VerifierNotInitialised)
        if not verified:
          return err(StatelessLedgerError.InvalidProof)

  ok(ValidSignedMantleTx(htx: htx))

func validateGenesisTxStateless*(
    tx: SignedMantleTx
): Result[ValidGenesisMantleTx, StatelessLedgerError] =
  ## Stateless genesis checks; no proof is verified.
  ?validateGenesisTxStructural(tx)
  let htx = createGenesisHtx(tx).valueOr:
    return err(error.toStatelessLedgerError)
  ok(ValidGenesisMantleTx(ValidSignedMantleTx(htx: htx)))

when defined(unittest) or defined(test):
  func createValidTxForTest*(htx: HashedSignedMantleTx): ValidSignedMantleTx =
    ValidSignedMantleTx(htx: htx)

  func createValidGenesisTxForTest*(htx: HashedSignedMantleTx): ValidGenesisMantleTx =
    ValidGenesisMantleTx(ValidSignedMantleTx(htx: htx))

{.pop.}
