# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import unittest2
import ../../../logos_chain/bedrock/mantle/proofs
import ../../../logos_chain/bedrock/mantle/operations

suite "bedrock/mantle/proofs":
  test "proofType maps concrete proof variants to canonical families":
    check proofType(OpProof(
      kind: opfChannelInscribe,
      ed25519SigProof: default(Ed25519SigProof),
    )) == ptEd25519Sig

    check proofType(OpProof(
      kind: opfTransfer,
      transferProof: default(ZkSigProof),
    )) == ptZkSig
    check proofType(OpProof(
      kind: opfChannelDeposit,
      channelDepositProof: default(ZkSigProof),
    )) == ptZkSig
    check proofType(OpProof(
      kind: opfSdpWithdraw,
      sdpWithdrawProof: default(ZkSigProof),
    )) == ptZkSig
    check proofType(OpProof(
      kind: opfSdpActive,
      sdpActiveProof: default(ZkSigProof),
    )) == ptZkSig

    check proofType(OpProof(
      kind: opfSdpDeclare,
      declarationProof: ZkAndEd25519SigsProof(
        zkSig: default(ZkSigProof),
        ed25519Sig: default(Ed25519SigProof),
      ),
    )) == ptZkAndEd25519Sigs

    check proofType(OpProof(
      kind: opfChannelWithdraw,
      channelWithdrawOpProof: ChannelWithdrawOpProof(signatures: @[], indexes: @[]),
    )) == ptChannelWithdraw
    check proofType(OpProof(
      kind: opfChannelConfig,
      channelConfigOpProof: ChannelWithdrawOpProof(signatures: @[], indexes: @[]),
    )) == ptChannelWithdraw

    check proofType(OpProof(
      kind: opfLeaderClaim,
      proofOfClaimProof: default(ProofOfClaimProof),
    )) == ptProofOfClaim

{.pop.}
