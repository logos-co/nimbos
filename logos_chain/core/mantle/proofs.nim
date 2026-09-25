# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle proof domain types.
## Spec: [Bedrock v1.1 — Mantle Specification v1.10.0](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md)

{.push raises: [], gcsafe.}

import
  ./[primitives, opcodes, operations],
  ../crypto/types,
  libp2p/crypto/ed25519/ed25519

type
  OpProofKind* {.pure.} = enum
    opfTransfer
    opfChannelInscribe
    opfChannelDeposit
    opfChannelWithdraw
    opfChannelTransfer
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

  ChannelMultiSigProof* = object
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
    of opfChannelWithdraw: channelWithdrawOpProof*: ChannelMultiSigProof
    of opfChannelTransfer: channelTransferOpProof*: ChannelMultiSigProof
    of opfLeaderClaim: proofOfClaimProof*: ProofOfClaimProof
    of opfChannelConfig: channelConfigOpProof*: ChannelMultiSigProof

func `==`*(a, b: ChannelMultiSigProof): bool {.raises: [].} =
  if a.signatures.len != b.signatures.len or a.indexes.len != b.indexes.len:
    return false
  for i in 0 ..< a.signatures.len:
    if a.signatures[i] != b.signatures[i]:
      return false
  for i in 0 ..< a.indexes.len:
    if a.indexes[i] != b.indexes[i]:
      return false
  true

func `==`*(a, b: ZkAndEd25519SigsProof): bool {.raises: [].} =
  a.zkSig == b.zkSig and a.ed25519Sig == b.ed25519Sig

func `==`*(a, b: OpProof): bool {.raises: [].} =
  if a.kind != b.kind:
    return false
  case a.kind
  of opfTransfer: a.transferProof == b.transferProof
  of opfChannelDeposit: a.channelDepositProof == b.channelDepositProof
  of opfSdpDeclare: a.declarationProof == b.declarationProof
  of opfSdpWithdraw: a.sdpWithdrawProof == b.sdpWithdrawProof
  of opfSdpActive: a.sdpActiveProof == b.sdpActiveProof
  of opfChannelInscribe: a.ed25519SigProof == b.ed25519SigProof
  of opfChannelWithdraw: a.channelWithdrawOpProof == b.channelWithdrawOpProof
  of opfChannelTransfer: a.channelTransferOpProof == b.channelTransferOpProof
  of opfLeaderClaim: a.proofOfClaimProof == b.proofOfClaimProof
  of opfChannelConfig: a.channelConfigOpProof == b.channelConfigOpProof

func sameOpProofs*(a, b: openArray[OpProof]): bool {.raises: [].} =
  if a.len != b.len:
    return false
  for i in 0 ..< a.len:
    if not (a[i] == b[i]):
      return false
  true

func proofTypeForKind(kind: OpProofKind): ProofType =
  ## Canonical mapping from OpProof variant to proof family.
  case kind
  of opfChannelInscribe:
    ptEd25519Sig
  of opfTransfer, opfChannelDeposit, opfSdpWithdraw, opfSdpActive:
    ptZkSig
  of opfSdpDeclare:
    ptZkAndEd25519Sigs
  of opfChannelWithdraw, opfChannelTransfer, opfChannelConfig:
    ptChannelWithdraw
  of opfLeaderClaim:
    ptProofOfClaim

func defaultOpProofForOpcode*(opcode: Opcode): Result[OpProof, EncodingError] =
  ## Canonical default/empty proof value for a given opcode.
  case opcode
  of OpTransfer:
    ok(OpProof(kind: opfTransfer, transferProof: DefaultZkSignature))
  of OpChannelInscribe:
    ok(OpProof(kind: opfChannelInscribe, ed25519SigProof: DefaultEd25519Signature))
  of OpChannelDeposit:
    ok(OpProof(kind: opfChannelDeposit, channelDepositProof: DefaultZkSignature))
  of OpChannelWithdraw:
    ok(OpProof(
      kind: opfChannelWithdraw,
      channelWithdrawOpProof: ChannelMultiSigProof(signatures: @[], indexes: @[]),
    ))
  of OpChannelTransfer:
    ok(OpProof(
      kind: opfChannelTransfer,
      channelTransferOpProof: ChannelMultiSigProof(signatures: @[], indexes: @[]),
    ))
  of OpSdpDeclare:
    ok(OpProof(
      kind: opfSdpDeclare,
      declarationProof: ZkAndEd25519SigsProof(
        zkSig: DefaultZkSignature,
        ed25519Sig: DefaultEd25519Signature,
      ),
    ))
  of OpSdpWithdraw:
    ok(OpProof(kind: opfSdpWithdraw, sdpWithdrawProof: DefaultZkSignature))
  of OpSdpActive:
    ok(OpProof(kind: opfSdpActive, sdpActiveProof: DefaultZkSignature))
  of OpLeaderClaim:
    ok(OpProof(kind: opfLeaderClaim, proofOfClaimProof: DefaultCompressedGroth16Proof))
  of OpChannelConfig:
    ok(OpProof(
      kind: opfChannelConfig,
      channelConfigOpProof: ChannelMultiSigProof(signatures: @[], indexes: @[]),
    ))
  else:
    err(EncodingError.UnsupportedOpcode)

func proofType*(proof: OpProof): ProofType =
  ## Proof family for a concrete proof value.
  proofTypeForKind(proof.kind)

func expectedOpProofKindForOpcode*(opcode: Opcode): Result[OpProofKind, EncodingError] =
  case opcode
  of OpTransfer: ok(opfTransfer)
  of OpChannelInscribe: ok(opfChannelInscribe)
  of OpChannelDeposit: ok(opfChannelDeposit)
  of OpChannelWithdraw: ok(opfChannelWithdraw)
  of OpChannelTransfer: ok(opfChannelTransfer)
  of OpSdpDeclare: ok(opfSdpDeclare)
  of OpSdpWithdraw: ok(opfSdpWithdraw)
  of OpSdpActive: ok(opfSdpActive)
  of OpLeaderClaim: ok(opfLeaderClaim)
  of OpChannelConfig: ok(opfChannelConfig)
  else:
    err(EncodingError.UnsupportedOpcode)

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

func encodeChannelMultiSigProof*(
  signatures: openArray[Ed25519Signature], indexes: openArray[ChannelKeyIndex]
): Result[seq[byte], EncodingError] =
  ## ChannelMultiSigProof = SignatureCount * IndexedEd25519Signature
  if signatures.len != indexes.len:
    return err(EncodingError.MultiSigSignaturesMismatch)
  if signatures.len > int(high(uint16)):
    return err(EncodingError.MultiSigCountExceeded)
  for i in 1 ..< indexes.len:
    if uint16(indexes[i - 1]) >= uint16(indexes[i]):
      return err(EncodingError.MultiSigSignaturesMismatch)

  var res: seq[byte]
  let countBytes = encodeSignatureCount(SignatureCount(uint16(signatures.len)))
  res.add(countBytes[0])
  res.add(countBytes[1])
  for i in 0 ..< signatures.len:
    let indexedSig = encodeIndexedEd25519Signature(signatures[i], indexes[i])
    res.add(indexedSig)
  ok(res)

func encodeOpProof*(proof: OpProof): Result[seq[byte], EncodingError] =
  ## OpProof =
  ##   Ed25519SigProof /
  ##   ZkSigProof /
  ##   ZkAndEd25519SigsProof /
  ##   ChannelMultiSigProof /
  ##   ProofOfClaimProof
  ##
  ## Additional local variants:
  ## - opfChannelDeposit: ZkSigProof
  ## - opfChannelTransfer, opfChannelConfig: encoded as
  ##   SignatureCount * IndexedEd25519Signature
  case proof.kind
  of opfChannelInscribe:
    ok(@(encodeEd25519SigProof(proof.ed25519SigProof)))
  of opfTransfer:
    ok(@(encodeZkSigProof(proof.transferProof)))
  of opfSdpWithdraw:
    ok(@(encodeZkSigProof(proof.sdpWithdrawProof)))
  of opfSdpActive:
    ok(@(encodeZkSigProof(proof.sdpActiveProof)))
  of opfSdpDeclare:
    ok(@(encodeZkAndEd25519SigsProof(
      proof.declarationProof.zkSig, proof.declarationProof.ed25519Sig
    )))
  of opfChannelWithdraw:
    encodeChannelMultiSigProof(
      proof.channelWithdrawOpProof.signatures, proof.channelWithdrawOpProof.indexes
    )
  of opfChannelTransfer:
    encodeChannelMultiSigProof(
      proof.channelTransferOpProof.signatures, proof.channelTransferOpProof.indexes
    )
  of opfLeaderClaim:
    ok(@(encodeProofOfClaimProof(proof.proofOfClaimProof)))
  of opfChannelConfig:
    encodeChannelMultiSigProof(
      proof.channelConfigOpProof.signatures, proof.channelConfigOpProof.indexes
    )
  of opfChannelDeposit:
    ok(@(encodeZkSigProof(proof.channelDepositProof)))

func byteLen*(proof: OpProof): int =
  ## Exact wire byte length of an OpProof without allocating buffers.
  case proof.kind
  of opfChannelInscribe:
    sizeof(Ed25519Signature)
  of opfTransfer, opfChannelDeposit, opfSdpWithdraw, opfSdpActive:
    sizeof(ZkSignature)
  of opfSdpDeclare:
    sizeof(ZkSignature) + sizeof(Ed25519Signature)
  of opfLeaderClaim:
    sizeof(CompressedGroth16Proof)
  of opfChannelWithdraw:
    template w: untyped = proof.channelWithdrawOpProof
    sizeof(SignatureCount) + w.signatures.len * (sizeof(Ed25519Signature) + sizeof(ChannelKeyIndex))
  of opfChannelTransfer:
    template t: untyped = proof.channelTransferOpProof
    sizeof(SignatureCount) + t.signatures.len * (sizeof(Ed25519Signature) + sizeof(ChannelKeyIndex))
  of opfChannelConfig:
    template c: untyped = proof.channelConfigOpProof
    sizeof(SignatureCount) + c.signatures.len * (sizeof(Ed25519Signature) + sizeof(ChannelKeyIndex))

func byteLen*(proofs: openArray[OpProof]): int =
  ## Exact wire byte length of an OpProofs sequence without allocating buffers.
  var total = 0
  for p in proofs:
    total += byteLen(p)
  total

func decodeProofOfClaimProof*(data: openArray[byte]): Result[ProofOfClaimProof, DecodingError] =
  decodeGroth16(data)


func readEd25519Signature(data: openArray[byte], pos: var int): Result[Ed25519Signature, DecodingError] =
  var sig: Ed25519Signature
  let raw = ?readFixed[EdSignatureSize](data, pos)
  if not sig.init(raw):
    return err(DecodingError.InvalidSignature)
  ok(sig)

func readIndexedEd25519Signature(data: openArray[byte], pos: var int): Result[(Ed25519Signature, ChannelKeyIndex), DecodingError] =
  let signature = ?readEd25519Signature(data, pos)
  let index = ChannelKeyIndex(?readLe[uint16](data, pos))
  ok((signature, index))

func decodeEd25519SigProof*(data: openArray[byte]): Result[Ed25519Signature, DecodingError] =
  decodeEd25519Signature(data)

func decodeZkSigProof*(data: openArray[byte]): Result[ZkSignature, DecodingError] =
  decodeZkSignature(data)

func decodeZkAndEd25519SigsProof*(data: openArray[byte]): Result[ZkAndEd25519SigsProof, DecodingError] =
  var pos = 0
  let zkSig = ?readFixed[128](data, pos)
  let ed25519Sig = ?readEd25519Signature(data, pos)
  ?finishDecode(data, pos)
  ok(ZkAndEd25519SigsProof(zkSig: zkSig, ed25519Sig: ed25519Sig))

func readChannelMultiSigProof(data: openArray[byte], pos: var int): Result[ChannelMultiSigProof, DecodingError] =
  let count = SignatureCount(?readLe[uint16](data, pos))
  var signatures = newSeqOfCap[Ed25519Signature](count)
  var indexes = newSeqOfCap[ChannelKeyIndex](count)
  var prevIndex = ChannelKeyIndex(0)
  var havePrev = false
  for _ in 0 ..< int(count):
    let (signature, index) = ?readIndexedEd25519Signature(data, pos)
    if havePrev and uint16(index) <= uint16(prevIndex):
      return err(DecodingError.MultiSigIndicesNonIncreasing)
    signatures.add signature
    indexes.add index
    prevIndex = index
    havePrev = true
  ok(ChannelMultiSigProof(signatures: signatures, indexes: indexes))

func decodeChannelMultiSigProof*(data: openArray[byte]): Result[ChannelMultiSigProof, DecodingError] =
  var pos = 0
  let res = ?readChannelMultiSigProof(data, pos)
  ?finishDecode(data, pos)
  ok(res)

func readOpProof*(data: openArray[byte], pos: var int, kind: OpProofKind): Result[OpProof, DecodingError] =
  case kind
  of opfChannelInscribe:
    let sig = ?readEd25519Signature(data, pos)
    ok(OpProof(kind: opfChannelInscribe, ed25519SigProof: sig))
  of opfTransfer:
    let proof = ?readFixed[128](data, pos)
    ok(OpProof(kind: opfTransfer, transferProof: proof))
  of opfSdpWithdraw:
    let proof = ?readFixed[128](data, pos)
    ok(OpProof(kind: opfSdpWithdraw, sdpWithdrawProof: proof))
  of opfSdpActive:
    let proof = ?readFixed[128](data, pos)
    ok(OpProof(kind: opfSdpActive, sdpActiveProof: proof))
  of opfSdpDeclare:
    let zkSig = ?readFixed[128](data, pos)
    let ed25519Sig = ?readEd25519Signature(data, pos)
    ok(OpProof(
      kind: opfSdpDeclare,
      declarationProof: ZkAndEd25519SigsProof(zkSig: zkSig, ed25519Sig: ed25519Sig),
    ))
  of opfChannelWithdraw:
    let proof = ?readChannelMultiSigProof(data, pos)
    ok(OpProof(
      kind: opfChannelWithdraw,
      channelWithdrawOpProof: proof,
    ))
  of opfChannelTransfer:
    let proof = ?readChannelMultiSigProof(data, pos)
    ok(OpProof(
      kind: opfChannelTransfer,
      channelTransferOpProof: proof,
    ))
  of opfLeaderClaim:
    let proof = ?readFixed[128](data, pos)
    ok(OpProof(kind: opfLeaderClaim, proofOfClaimProof: proof))
  of opfChannelConfig:
    let proof = ?readChannelMultiSigProof(data, pos)
    ok(OpProof(
      kind: opfChannelConfig,
      channelConfigOpProof: proof,
    ))
  of opfChannelDeposit:
    let proof = ?readFixed[128](data, pos)
    ok(OpProof(kind: opfChannelDeposit, channelDepositProof: proof))

func decodeOpProof*(data: openArray[byte], kind: OpProofKind): Result[OpProof, DecodingError] =
  var pos = 0
  let res = ?readOpProof(data, pos, kind)
  ?finishDecode(data, pos)
  ok(res)

func encodeOpsProofs*(ops: openArray[Op], proofs: openArray[OpProof]): Result[seq[byte], EncodingError] =
  ## OpsProofs = *OpProof
  ## 1. Length must equal OpCount.
  ## 2. type(OpProofs[i]) == ProofFor(Op[i]).
  if proofs.len != ops.len:
    return err(EncodingError.ProofCountMismatch)
  var res: seq[byte]
  for i in 0 ..< proofs.len:
    let expectedKind = ?expectedOpProofKindForOpcode(ops[i].opcode)
    if proofs[i].kind != expectedKind:
      return err(EncodingError.ProofKindMismatch)
    let encoded = ?encodeOpProof(proofs[i])
    res.add(encoded)
  ok(res)

func decodeOpsProofs*(ops: openArray[Op], data: openArray[byte]): Result[seq[OpProof], DecodingError] =
  if ops.len > 0 and data.len == 0:
    return err(DecodingError.ProofCountMismatch)
  var pos = 0
  var res = newSeqOfCap[OpProof](ops.len)
  for i in 0 ..< ops.len:
    let kind = expectedOpProofKindForOpcode(ops[i].opcode).valueOr:
      return err(DecodingError.UnsupportedOpcode)
    res.add ?readOpProof(data, pos, kind)
  ?finishDecode(data, pos)
  ok(res)

{.pop.}
