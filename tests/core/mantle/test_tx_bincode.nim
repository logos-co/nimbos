# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import ../../testutil
import bincode
import ../../../logos_chain/core/mantle/[operations, proofs, tx_bincode, tx_types]

const allOpcodes = [
  OpTransfer,
  OpChannelInscribe,
  OpChannelDeposit,
  OpChannelWithdraw,
  OpSdpDeclare,
  OpSdpWithdraw,
  OpSdpActive,
  OpLeaderClaim,
  OpChannelConfig,
]

proc checkOpProofEqual(a, b: OpProof) =
  check a.kind == b.kind
  case a.kind
  of opfTransfer:
    check a.transferProof == b.transferProof
  of opfChannelInscribe:
    check a.ed25519SigProof == b.ed25519SigProof
  of opfChannelDeposit:
    check a.channelDepositProof == b.channelDepositProof
  of opfChannelWithdraw:
    check a.channelWithdrawOpProof.signatures == b.channelWithdrawOpProof.signatures
    check a.channelWithdrawOpProof.indexes == b.channelWithdrawOpProof.indexes
  of opfSdpDeclare:
    check a.declarationProof.zkSig == b.declarationProof.zkSig
    check a.declarationProof.ed25519Sig == b.declarationProof.ed25519Sig
  of opfSdpWithdraw:
    check a.sdpWithdrawProof == b.sdpWithdrawProof
  of opfSdpActive:
    check a.sdpActiveProof == b.sdpActiveProof
  of opfLeaderClaim:
    check a.proofOfClaimProof == b.proofOfClaimProof
  of opfChannelConfig:
    check a.channelConfigOpProof.signatures == b.channelConfigOpProof.signatures
    check a.channelConfigOpProof.indexes == b.channelConfigOpProof.indexes

proc checkOpEqual(a, b: Op) =
  check a.opcode == b.opcode
  check a.payload.kind == b.payload.kind
  case a.payload.kind
  of Transfer:
    check a.payload.transfer == b.payload.transfer
  of ChannelInscribe:
    check a.payload.channelInscribe.channelId == b.payload.channelInscribe.channelId
    check a.payload.channelInscribe.inscription == b.payload.channelInscribe.inscription
    check a.payload.channelInscribe.parent == b.payload.channelInscribe.parent
    check a.payload.channelInscribe.signer == b.payload.channelInscribe.signer
  of ChannelDeposit:
    check a.payload.channelDeposit == b.payload.channelDeposit
  of ChannelWithdraw:
    check a.payload.channelWithdraw == b.payload.channelWithdraw
  of SdpDeclare:
    check a.payload.sdpDeclare.serviceType == b.payload.sdpDeclare.serviceType
    check a.payload.sdpDeclare.locators == b.payload.sdpDeclare.locators
    check a.payload.sdpDeclare.providerId == b.payload.sdpDeclare.providerId
    check a.payload.sdpDeclare.zkId == b.payload.sdpDeclare.zkId
    check a.payload.sdpDeclare.lockedNoteId == b.payload.sdpDeclare.lockedNoteId
  of SdpWithdraw:
    check a.payload.sdpWithdraw == b.payload.sdpWithdraw
  of SdpActive:
    check a.payload.sdpActive == b.payload.sdpActive
  of LeaderClaim:
    check a.payload.leaderClaim == b.payload.leaderClaim
  of ChannelConfig:
    check a.payload.channelConfig == b.payload.channelConfig

proc checkSignedMantleTxEqual(a, b: SignedMantleTx) =
  check a.tx.executionGasPrice == b.tx.executionGasPrice
  check a.tx.permanentStorageGasPrice == b.tx.permanentStorageGasPrice
  check a.tx.ops.len == b.tx.ops.len
  check a.opProofs.len == b.opProofs.len
  for i in 0 ..< a.tx.ops.len:
    checkOpEqual(a.tx.ops[i], b.tx.ops[i])
    checkOpProofEqual(a.opProofs[i], b.opProofs[i])

func signedTxWithAllOps(): SignedMantleTx =
  var ops: seq[Op]
  var proofs: seq[OpProof]
  for opcode in allOpcodes:
    ops.add defaultOpForOpcode(opcode)
    proofs.add defaultOpProofForOpcode(opcode)
  SignedMantleTx(
    tx: MantleTx(
      ops: ops,
      executionGasPrice: 9'u64,
      permanentStorageGasPrice: 10'u64,
    ),
    opProofs: proofs,
  )

proc checkSignedMantleTxRoundtrip(signed: SignedMantleTx) {.raises: [BincodeError, IOError].} =
  let
    wire = serializeSignedMantleTxToSeq(signed)
    back = deserializeSignedMantleTx(wire)
  checkSignedMantleTxEqual(signed, back)

suite "core/mantle/tx_bincode":
  test "serializeSignedMantleTxToSeq roundtrips deserializeSignedMantleTx (empty tx)":
    let signed = SignedMantleTx(
      tx: MantleTx(
        ops: @[],
        executionGasPrice: 7'u64,
        permanentStorageGasPrice: 8'u64,
      ),
      opProofs: @[],
    )
    checkSignedMantleTxRoundtrip(signed)

  test "serializeSignedMantleTxToSeq roundtrips deserializeSignedMantleTx (all op kinds)":
    checkSignedMantleTxRoundtrip(signedTxWithAllOps())

  test "deserializeSignedMantleTxAt reads one prefixed tx inside a longer buffer":
    let signed = signedTxWithAllOps()
    try:
      let wire = serializeSignedMantleTxToSeq(signed)
      var buf = wire
      buf.add @[0xFF'u8]
      let (back, used) = deserializeSignedMantleTxAt(buf)
      check used == wire.len
      checkSignedMantleTxEqual(signed, back)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()

{.pop.}
