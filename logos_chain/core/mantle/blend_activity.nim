# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Blend service activity metadata carried by SDP Active operations.
## Spec: [Blend Protocol](https://github.com/logos-co/logos-lips/blob/a2a85cbe444e9727ae7f42b2f6d6f4c6bf8d63e9/docs/blockchain/raw/blend-protocol.md)

{.push raises: [], gcsafe.}

import
  results,
  stew/endians2,
  libp2p/crypto/ed25519/ed25519,
  ../crypto/types

const
  ActiveMetadataBlendType* = 0x01'u8
    ## metadata_type selector for Blend activity metadata.
  BlendActiveMetadataVersion* = 0x01'u8
    ## Version of the Blend activity proof format.
  ActivityMetadataLen* = 230
    ## type(1) ‖ version(1) ‖ epoch u32 LE(4) ‖ signing key(32) ‖
    ## key nullifier frLE(32) ‖ quota proof(128) ‖ selection frLE(32).

type
  ProofOfQuota* = object
    keyNullifier*: FieldElement
    proof*: CompressedGroth16Proof
      ## Opaque until the proof-of-quota verifier lands.

  ActivityProof* = object
    epoch*: uint32
    signingKey*: Ed25519PublicKey
    proofOfQuota*: ProofOfQuota
    proofOfSelection*: FieldElement

const ActivityProofBodyLen* = 224
  ## signing key(32) ‖ key nullifier frLE(32) ‖ quota proof(128) ‖
  ## selection randomness frLE(32); also the blending-token hash preimage.

func encodeActivityProofBody*(
    signingKey: Ed25519PublicKey,
    proofOfQuota: ProofOfQuota,
    selectionRandomness: FieldElement,
): array[ActivityProofBodyLen, byte] =
  ## The proof fields after the epoch, in wire order.
  # The lottery hashes exactly these bytes, so wire form and token
  # preimage must come from one encoder.
  result[0 ..< 32] = encodeEd25519PublicKey(signingKey)
  result[32 ..< 64] = encodeFieldElement(proofOfQuota.keyNullifier)
  result[64 ..< 192] = proofOfQuota.proof
  result[192 ..< 224] = encodeFieldElement(selectionRandomness)

func encodeActivityMetadata*(proof: ActivityProof): seq[byte] =
  ## Full SDP Active metadata payload for a Blend activity proof.
  var res = newSeqOfCap[byte](ActivityMetadataLen)
  res.add ActiveMetadataBlendType
  res.add BlendActiveMetadataVersion
  res.add encodeLe(proof.epoch)
  res.add encodeActivityProofBody(
    proof.signingKey, proof.proofOfQuota, proof.proofOfSelection)
  res

func decodeActivityMetadata*(
    metadata: openArray[byte]
): Result[ActivityProof, cstring] =
  ## Parses a Blend activity metadata payload, rejecting non-canonical
  ## field elements.
  if metadata.len != ActivityMetadataLen:
    return err("activity metadata: wrong length")
  if metadata[0] != ActiveMetadataBlendType:
    return err("activity metadata: unknown metadata type")
  if metadata[1] != BlendActiveMetadataVersion:
    return err("activity metadata: unsupported version")
  var proof = ActivityProof(
    epoch: uint32.fromBytesLE(metadata.toOpenArray(2, 5)))
  # The signing key's point validity is checked with proof-of-quota
  # verification, where the key is a public input; the codec checks
  # length only.
  if not proof.signingKey.init(metadata.toOpenArray(6, 37)):
    return err("activity metadata: bad signing key")
  proof.proofOfQuota.keyNullifier = frFromBytesLE(
      metadata.toOpenArray(38, 69)).valueOr:
    return err("activity metadata: non-canonical key nullifier")
  proof.proofOfQuota.proof[0 ..< CompressedGroth16ProofBytes] =
    metadata.toOpenArray(70, 197)
  proof.proofOfSelection = frFromBytesLE(
      metadata.toOpenArray(198, 229)).valueOr:
    return err("activity metadata: non-canonical proof of selection")
  ok(proof)

{.pop.}
