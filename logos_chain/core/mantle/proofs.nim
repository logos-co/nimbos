# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle proof domain types.
## Spec: [v1.4 Mantle](https://nomos-tech.notion.site/v1-4-Mantle-335261aa09df8065a38acff4b25aee82)
##
## Wire encoding/decoding: [v1.3 Mantle Transaction Encoding](https://nomos-tech.notion.site/v1-3-Mantle-Transaction-Encoding-335261aa09df8051a8a6f325aa41f6a7)

{.push raises: [], gcsafe.}

import ./[primitives, opcodes, operations]
import ../crypto/types
import libp2p/crypto/ed25519/ed25519

type
  OpProofKind* {.pure.} = enum
    opfTransfer
    opfChannelInscribe
    opfChannelDeposit
    opfChannelWithdraw
    opfSdpDeclare
    opfSdpWithdraw
    opfSdpActive
    opfLeaderClaim
    opfChannelConfig

  ProofType* {.pure.} = enum
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

func defaultOpProofForOpcode*(opcode: Opcode): OpProof =
  ## Canonical default/empty proof value for a given opcode.
  case opcode
  of OpTransfer:
    OpProof(kind: opfTransfer, transferProof: DefaultZkSignature)
  of OpChannelInscribe:
    OpProof(kind: opfChannelInscribe, ed25519SigProof: DefaultEd25519Signature)
  of OpChannelDeposit:
    OpProof(kind: opfChannelDeposit, channelDepositProof: DefaultZkSignature)
  of OpChannelWithdraw:
    OpProof(
      kind: opfChannelWithdraw,
      channelWithdrawOpProof: ChannelWithdrawOpProof(signatures: @[], indexes: @[]),
    )
  of OpSdpDeclare:
    OpProof(
      kind: opfSdpDeclare,
      declarationProof: ZkAndEd25519SigsProof(
        zkSig: DefaultZkSignature,
        ed25519Sig: DefaultEd25519Signature,
      ),
    )
  of OpSdpWithdraw:
    OpProof(kind: opfSdpWithdraw, sdpWithdrawProof: DefaultZkSignature)
  of OpSdpActive:
    OpProof(kind: opfSdpActive, sdpActiveProof: DefaultZkSignature)
  of OpLeaderClaim:
    OpProof(kind: opfLeaderClaim, proofOfClaimProof: DefaultCompressedGroth16Proof)
  of OpChannelConfig:
    OpProof(
      kind: opfChannelConfig,
      channelConfigOpProof: ChannelWithdrawOpProof(signatures: @[], indexes: @[]),
    )
  else:
    doAssert false, "unknown opcode for default op proof: " & $opcode
    default(OpProof)

func proofType*(proof: OpProof): ProofType =
  ## Proof family for a concrete proof value.
  proofTypeForKind(proof.kind)

func expectedOpProofKindForOpcode*(opcode: Opcode): OpProofKind =
  case opcode
  of OpTransfer: opfTransfer
  of OpChannelInscribe: opfChannelInscribe
  of OpChannelDeposit: opfChannelDeposit
  of OpChannelWithdraw: opfChannelWithdraw
  of OpSdpDeclare: opfSdpDeclare
  of OpSdpWithdraw: opfSdpWithdraw
  of OpSdpActive: opfSdpActive
  of OpLeaderClaim: opfLeaderClaim
  of OpChannelConfig: opfChannelConfig
  else:
    doAssert false, "unknown opcode for OpProof expectation: " & $opcode
    default(OpProofKind)

func encodeProofOfClaimProof*(value: ProofOfClaimProof): array[128, byte] =
  ## ProofOfClaimProof = Groth16
  encodeGroth16(value)

func encodeIndexedEd25519Signature*(
    signature: Ed25519Signature, index: ChannelKeyIndex
): array[66, byte] =
  ## IndexedEd25519Signature = Ed25519Signature || ChannelKeyIndex
  var res: array[66, byte]
  res[0 ..< 64] = encodeEd25519Signature(signature)
  res[64 ..< 66] = encodeChannelKeyIndex(index)
  res

func encodeEd25519SigProof*(value: Ed25519Signature): array[64, byte] =
  ## Ed25519SigProof = Ed25519Signature
  encodeEd25519Signature(value)

func encodeZkSigProof*(value: ZkSignature): array[128, byte] =
  ## ZkSigProof = ZkSignature
  encodeZkSignature(value)

func encodeZkAndEd25519SigsProof*(
    zkSig: ZkSignature, ed25519Sig: Ed25519Signature
): array[192, byte] =
  ## ZkAndEd25519SigsProof = ZkSignature || Ed25519Signature
  var res: array[192, byte]
  res[0 ..< 128] = encodeZkSignature(zkSig)
  res[128 ..< 192] = encodeEd25519Signature(ed25519Sig)
  res

func encodeChannelWithdrawOpProof*(
  signatures: openArray[Ed25519Signature], indexes: openArray[ChannelKeyIndex]
): seq[byte] =
  ## ChannelWithdrawOpProof = SignatureCount * IndexedEd25519Signature
  doAssert signatures.len == indexes.len,
    "ChannelWithdrawOpProof: signatures and indexes length mismatch"
  doAssert signatures.len <= int(high(uint16)),
    "ChannelWithdrawOpProof: too many signatures for UINT16 SignatureCount"
  for i in 1 ..< indexes.len:
    doAssert uint16(indexes[i - 1]) < uint16(indexes[i]),
      "ChannelWithdrawOpProof: indexes must be strictly increasing (ordered, no duplicates)"

  var res: seq[byte]
  let countBytes = encodeSignatureCount(SignatureCount(uint16(signatures.len)))
  res.add(countBytes[0])
  res.add(countBytes[1])
  for i in 0 ..< signatures.len:
    let indexedSig = encodeIndexedEd25519Signature(signatures[i], indexes[i])
    res.add(indexedSig)
  res

func encodeOpProof*(proof: OpProof): seq[byte] =
  ## OpProof =
  ##   Ed25519SigProof /
  ##   ZkSigProof /
  ##   ZkAndEd25519SigsProof /
  ##   ChannelWithdrawOpProof /
  ##   ProofOfClaimProof
  ##
  ## Additional local variants:
  ## - opfChannelDeposit: ZkSigProof
  ## - opfChannelConfig: encoded as SignatureCount * IndexedEd25519Signature
  case proof.kind
  of opfChannelInscribe:
    @(encodeEd25519SigProof(proof.ed25519SigProof))
  of opfTransfer:
    @(encodeZkSigProof(proof.transferProof))
  of opfSdpWithdraw:
    @(encodeZkSigProof(proof.sdpWithdrawProof))
  of opfSdpActive:
    @(encodeZkSigProof(proof.sdpActiveProof))
  of opfSdpDeclare:
    @(encodeZkAndEd25519SigsProof(
      proof.declarationProof.zkSig, proof.declarationProof.ed25519Sig
    ))
  of opfChannelWithdraw:
    encodeChannelWithdrawOpProof(
      proof.channelWithdrawOpProof.signatures, proof.channelWithdrawOpProof.indexes
    )
  of opfLeaderClaim:
    @(encodeProofOfClaimProof(proof.proofOfClaimProof))
  of opfChannelConfig:
    encodeChannelWithdrawOpProof(
      proof.channelConfigOpProof.signatures, proof.channelConfigOpProof.indexes
    )
  of opfChannelDeposit:
    @(encodeZkSigProof(proof.channelDepositProof))

func decodeProofOfClaimProof*(data: openArray[byte]): ProofOfClaimProof {.raises: [DecodingError].} =
  decodeGroth16(data)


proc readEd25519Signature(data: openArray[byte], pos: var int): Ed25519Signature {.raises: [DecodingError].} =
  var sig: Ed25519Signature
  if not sig.init(readFixed[EdSignatureSize](data, pos)):
    raise newException(DecodingError, "invalid Ed25519 signature bytes")
  sig

proc readIndexedEd25519Signature(data: openArray[byte], pos: var int): (Ed25519Signature, ChannelKeyIndex) {.raises: [DecodingError].} =
  let signature = readEd25519Signature(data, pos)
  let index = ChannelKeyIndex(readLe[uint16](data, pos))
  (signature, index)

func decodeEd25519SigProof*(data: openArray[byte]): Ed25519Signature {.raises: [DecodingError].} =
  decodeEd25519Signature(data)

func decodeZkSigProof*(data: openArray[byte]): ZkSignature {.raises: [DecodingError].} =
  decodeZkSignature(data)

func decodeZkAndEd25519SigsProof*(data: openArray[byte]): ZkAndEd25519SigsProof {.raises: [DecodingError].} =
  var pos = 0
  let zkSig = readFixed[128](data, pos)
  let ed25519Sig = readEd25519Signature(data, pos)
  finishDecode(data, pos)
  ZkAndEd25519SigsProof(zkSig: zkSig, ed25519Sig: ed25519Sig)

proc readChannelWithdrawOpProof(data: openArray[byte], pos: var int): ChannelWithdrawOpProof {.raises: [DecodingError].} =
  let count = SignatureCount(readLe[uint16](data, pos))
  var signatures = newSeqOfCap[Ed25519Signature](count)
  var indexes = newSeqOfCap[ChannelKeyIndex](count)
  var prevIndex = ChannelKeyIndex(0)
  var havePrev = false
  for _ in 0 ..< int(count):
    let (signature, index) = readIndexedEd25519Signature(data, pos)
    if havePrev and uint16(index) <= uint16(prevIndex):
      raise newException(DecodingError, "ChannelWithdrawOpProof indexes not strictly increasing")
    signatures.add signature
    indexes.add index
    prevIndex = index
    havePrev = true
  ChannelWithdrawOpProof(signatures: signatures, indexes: indexes)

func decodeChannelWithdrawOpProof*(data: openArray[byte]): ChannelWithdrawOpProof {.raises: [DecodingError].} =
  var pos = 0
  let res = readChannelWithdrawOpProof(data, pos)
  finishDecode(data, pos)
  res

proc readOpProof*(data: openArray[byte], pos: var int, kind: OpProofKind): OpProof {.raises: [DecodingError].} =
  case kind
  of opfChannelInscribe:
    OpProof(kind: opfChannelInscribe, ed25519SigProof: readEd25519Signature(data, pos))
  of opfTransfer:
    OpProof(kind: opfTransfer, transferProof: readFixed[128](data, pos))
  of opfSdpWithdraw:
    OpProof(kind: opfSdpWithdraw, sdpWithdrawProof: readFixed[128](data, pos))
  of opfSdpActive:
    OpProof(kind: opfSdpActive, sdpActiveProof: readFixed[128](data, pos))
  of opfSdpDeclare:
    let zkSig = readFixed[128](data, pos)
    let ed25519Sig = readEd25519Signature(data, pos)
    OpProof(
      kind: opfSdpDeclare,
      declarationProof: ZkAndEd25519SigsProof(zkSig: zkSig, ed25519Sig: ed25519Sig),
    )
  of opfChannelWithdraw:
    OpProof(
      kind: opfChannelWithdraw,
      channelWithdrawOpProof: readChannelWithdrawOpProof(data, pos),
    )
  of opfLeaderClaim:
    OpProof(kind: opfLeaderClaim, proofOfClaimProof: readFixed[128](data, pos))
  of opfChannelConfig:
    OpProof(
      kind: opfChannelConfig,
      channelConfigOpProof: readChannelWithdrawOpProof(data, pos),
    )
  of opfChannelDeposit:
    OpProof(kind: opfChannelDeposit, channelDepositProof: readFixed[128](data, pos))

func decodeOpProof*(data: openArray[byte], kind: OpProofKind): OpProof {.raises: [DecodingError].} =
  var pos = 0
  let res = readOpProof(data, pos, kind)
  finishDecode(data, pos)
  res

func encodeOpsProofs*(ops: openArray[Op], proofs: openArray[OpProof]): seq[byte] =
  ## OpsProofs = *OpProof
  ## 1. Length must be <= OpCount.
  ## 2. type(OpProofs[i]) == ProofFor(Op[i]) for provided proofs.
  doAssert proofs.len <= ops.len,
    "OpsProofs length must be <= OpCount"
  var res: seq[byte]
  for i in 0 ..< proofs.len:
    doAssert proofs[i].kind == expectedOpProofKindForOpcode(ops[i].opcode),
      "OpProof variant does not match corresponding Op"
    let encoded = encodeOpProof(proofs[i])
    res.add(encoded)
  res

func decodeOpsProofs*(ops: openArray[Op], data: openArray[byte]): seq[OpProof] {.raises: [DecodingError].} =
  var pos = 0
  var res = newSeqOfCap[OpProof](ops.len)
  var i = 0
  while pos < data.len:
    if i >= ops.len:
      raise newException(DecodingError, "OpsProofs length exceeds OpCount")
    let kind = expectedOpProofKindForOpcode(ops[i].opcode)
    res.add readOpProof(data, pos, kind)
    inc i
  if res.len > ops.len:
    raise newException(DecodingError, "OpsProofs length exceeds OpCount")
  finishDecode(data, pos)
  res

{.pop.}
