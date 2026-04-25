# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle proof domain types.
## Spec: [v1.4 Mantle](https://nomos-tech.notion.site/v1-4-Mantle-335261aa09df8065a38acff4b25aee82)

{.push raises: [], gcsafe.}

import ./primitives

type
  OpProofKind* = enum
    opfTransfer
    opfChannelInscribe
    opfChannelDeposit
    opfChannelWithdraw
    opfSdpDeclare
    opfSdpWithdraw
    opfSdpActive
    opfLeaderClaim
    opfChannelConfig

  ## Canonical proof families used by Mantle operations.
  ProofType* = enum
    ptEd25519Sig
    ptZkSig
    ptZkAndEd25519Sigs
    ptChannelWithdraw
    ptProofOfClaim

  Ed25519SigProof* = Ed25519Signature
  ZkSigProof* = ZkSignature

  ZkAndEd25519SigsProof* = object
    zkSig*: ZkSignature
    ed25519Sig*: Ed25519Signature

  ChannelWithdrawOpProof* = object
    signatures*: seq[Ed25519Signature]
    indexes*: seq[ChannelKeyIndex]

  ProofOfClaimProof* = CompressedGroth16Proof

  ## Public inputs for proof-of-claim verification.
  ProofOfClaimPublic* = object
    voucherRoot*: ZkHash
    voucherNullifier*: ZkHash
    mantleTxHash*: ZkHash

  ProofOfClaimWitness* = object
    secretVoucher*: ZkHash
    voucherMerklePath*: seq[ZkHash]
    voucherMerklePathSelectors*: seq[bool]

  OpProof* = object
    case kind*: OpProofKind
    of opfTransfer: transferProof*: ZkSigProof
    of opfChannelDeposit: channelDepositProof*: ZkSigProof
    of opfSdpDeclare: declarationProof*: ZkAndEd25519SigsProof
    of opfSdpWithdraw: sdpWithdrawProof*: ZkSigProof
    of opfSdpActive: sdpActiveProof*: ZkSigProof
    of opfChannelInscribe: ed25519SigProof*: Ed25519SigProof
    of opfChannelWithdraw: channelWithdrawOpProof*: ChannelWithdrawOpProof
    of opfLeaderClaim: proofOfClaimProof*: ProofOfClaimProof
    of opfChannelConfig: channelConfigOpProof*: ChannelWithdrawOpProof

func proofTypeForKind(kind: OpProofKind): ProofType =
  ## Canonical mapping from OpProof variant to proof family.
  case kind
  of opfChannelInscribe:
    ptEd25519Sig
  of opfTransfer, opfChannelDeposit, opfSdpWithdraw, opfSdpActive:
    ptZkSig
  of opfSdpDeclare:
    ptZkAndEd25519Sigs
  of opfChannelWithdraw, opfChannelConfig:
    ptChannelWithdraw
  of opfLeaderClaim:
    ptProofOfClaim

func proofType*(proof: OpProof): ProofType =
  ## Proof family for a concrete proof value.
  proofTypeForKind(proof.kind)

{.pop.}
