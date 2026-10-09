# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Pure structural and stateless validation rules for Mantle transactions.
## Contains pure structural checks with zero cryptographic or ZK dependencies.
## Spec: [Bedrock v1.1 — Mantle Specification v1.10.0](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md)

{.push raises: [], gcsafe.}

import
  std/sequtils,
  results,
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
    GenesisInscription ## inscription not on the null channel from the null key
    GenesisInputs ## the genesis Transfer consumes notes
    TooManyOps ## more ops than the u8 wire count holds
    TooManyOutputs ## more outputs than the u8 wire count holds

export results, StatelessLedgerError

func toStatelessLedgerError*(err: EncodingError): StatelessLedgerError =
  case err
  of EncodingError.UnsupportedOpcode:
    StatelessLedgerError.UnsupportedOp
  of EncodingError.LocatorsCountExceeded:
    StatelessLedgerError.TooManyLocators
  of EncodingError.LocatorLengthExceeded:
    StatelessLedgerError.InvalidLocator
  of EncodingError.KeysCountExceeded:
    StatelessLedgerError.InvalidChannelConfig
  of EncodingError.OpsCountExceeded:
    StatelessLedgerError.TooManyOps
  of EncodingError.ProofCountMismatch, EncodingError.ProofKindMismatch,
     EncodingError.MultiSigCountExceeded, EncodingError.MultiSigSignaturesMismatch,
     EncodingError.MultiSigIndicesNonIncreasing,
     EncodingError.LengthExceeded, EncodingError.MetadataLengthExceeded,
     EncodingError.InscriptionLengthExceeded,
     EncodingError.InputsCountExceeded, EncodingError.OutputsCountExceeded:
    StatelessLedgerError.InvalidProof

func checkOpShape*(op: Op, proof: OpProof): Result[void, StatelessLedgerError] =
  ## The opcode is supported and matches both its payload and its proof kind.
  if not isSupportedOpcode(op.opcode) or op.opcode != opPayloadToOpcode(op.payload):
    return err(StatelessLedgerError.UnsupportedOp)
  let expectedProofKind = expectedOpProofKindForOpcode(op.opcode).valueOr:
    return err(error.toStatelessLedgerError)
  if proof.kind != expectedProofKind:
    return err(StatelessLedgerError.InvalidProof)
  ok()

func assert_valid_output*(outputs: openArray[Note]): Result[void, StatelessLedgerError] =
  ## Output Notes Validation: every value is non-zero.
  if outputs.anyIt(it.value == 0):
    return err(StatelessLedgerError.ZeroValueNote)
  ok()

func validateLocators*(decl: DeclarationMessage): Result[void, StatelessLedgerError] =
  ## 1 to `MaxSdpLocators` entries, each a valid locator.
  if decl.locators.len == 0:
    return err(StatelessLedgerError.EmptyLocators)
  if decl.locators.len > MaxSdpLocators:
    return err(StatelessLedgerError.TooManyLocators)
  if decl.locators.anyIt(not isValidLocator(it)):
    return err(StatelessLedgerError.InvalidLocator)
  ok()

func validateGenesisTxStateless*(
    tx: SignedMantleTx): Result[ValidGenesisMantleTx, StatelessLedgerError] =
  ## Stateless genesis checks; no proof is verified.
  template ops: untyped = tx.tx.ops
  if ops.len > MantleMaxOps:
    return err(StatelessLedgerError.TooManyOps)
  if ops.len < 2 or ops[0].payload.kind != Transfer or
      ops[1].payload.kind != ChannelInscribe or
      not ops.toOpenArray(2, ops.high).allIt(it.payload.kind == SdpDeclare):
    return err(StatelessLedgerError.GenesisShape)
  template inscribe: untyped = ops[1].payload.channelInscribe
  if inscribe.channelId != static(default(ChannelId)) or
      inscribe.signer != DefaultEd25519PublicKey:
    return err(StatelessLedgerError.GenesisInscription)
  if tx.opProofs.len != ops.len:
    return err(StatelessLedgerError.InvalidProof)
  for i in 0 ..< ops.len:
    ?checkOpShape(ops[i], tx.opProofs[i])
  template transfer: untyped = ops[0].payload.transfer
  if transfer.inputs.noteIds.len > 0:
    return err(StatelessLedgerError.GenesisInputs)
  if transfer.outputs.notes.len > MaxOutputs:
    return err(StatelessLedgerError.TooManyOutputs)
  ?assert_valid_output(transfer.outputs.notes)
  for op in ops.toOpenArray(2, ops.high):
    ?validateLocators(op.payload.sdpDeclare)
  ok(ValidGenesisMantleTx(tx))

{.pop.}
