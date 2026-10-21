# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Blend service activity metadata carried by SDP Active operations.
## Spec: [Blend Protocol v1.6.1](https://github.com/logos-co/logos-lips/blob/949faa9563027de366514247a2a62b0de2f8c45f/docs/blockchain/raw/blend-protocol.md)
## Spec: [Mantle Transaction Encoding v1.10.0](https://github.com/logos-co/logos-lips/blob/949faa9563027de366514247a2a62b0de2f8c45f/docs/blockchain/raw/mantle-transaction-encoding.md)

{.push raises: [], gcsafe.}

import
  results,
  stew/assign2,
  ../crypto/types

from ./primitives import EpochNumber

export EpochNumber

const
  ActiveMetadataBlendType = 0x01'u8
    ## ActivityMetadataType selector for Blend activity metadata.
  ActivityProofBodyLen* = 224
    ## signing key(32) ‖ key nullifier(32) ‖ quota proof(128) ‖ selection(32).
  ActivityMetadataLen* = 229
    ## tag(1) ‖ epoch u32 LE(4) ‖ ActivityProofBodyLen.

type
  ProofOfQuota* = object
    keyNullifier*: FieldElement
    proof*: CompressedGroth16Proof
      ## Opaque until the proof-of-quota verifier lands.

  ActivityProof* = object
    epoch*: EpochNumber
    signingKey*: Ed25519PublicKey
    proofOfQuota*: ProofOfQuota
    proofOfSelection*: FieldElement

func encodeActivityProofBody*(
    signingKey: Ed25519PublicKey,
    proofOfQuota: ProofOfQuota,
    selectionRandomness: FieldElement,
): array[ActivityProofBodyLen, byte] =
  ## The proof fields after the epoch, in wire order.
  # The lottery hashes exactly these bytes, so wire form and token
  # preimage must come from one encoder.
  var body {.noinit.}: array[ActivityProofBodyLen, byte]
  assign(body.toOpenArray(0, 31), encodeEd25519PublicKey(signingKey))
  assign(body.toOpenArray(32, 63), encodeFieldElement(proofOfQuota.keyNullifier))
  assign(body.toOpenArray(64, 191), proofOfQuota.proof)
  assign(body.toOpenArray(192, 223), encodeFieldElement(selectionRandomness))
  body

func encodeActivityMetadata*(proof: ActivityProof): array[ActivityMetadataLen, byte] =
  ## ActivityMetadata = ActivityMetadataType ‖ epoch ‖ activity proof body.
  var res {.noinit.}: array[ActivityMetadataLen, byte]
  res[0] = ActiveMetadataBlendType
  assign(res.toOpenArray(1, 4), encodeLe(proof.epoch))
  assign(res.toOpenArray(5, ActivityMetadataLen - 1), encodeActivityProofBody(
    proof.signingKey, proof.proofOfQuota, proof.proofOfSelection))
  res

func readActivityMetadata*(
    data: openArray[byte], pos: var int
): Result[ActivityProof, DecodingError] =
  ## Reads one tagged activity metadata at `pos`.
  if ?readByte(data, pos) != ActiveMetadataBlendType:
    return err(DecodingError.UnknownActivityMetadataType)
  var proof = ActivityProof(epoch: ?readLe[EpochNumber](data, pos))
  # The codec fixes the key length and checks nothing else. No later stage
  # decompresses the point. Proof-of-quota verification splits the raw key
  # bytes into two field elements.
  proof.signingKey = Ed25519PublicKey(data: ?readFixed[32](data, pos))
  proof.proofOfQuota.keyNullifier = ?decodeFieldElementAt(data, pos)
  proof.proofOfQuota.proof = ?readFixed[CompressedGroth16ProofBytes](data, pos)
  proof.proofOfSelection = ?decodeFieldElementAt(data, pos)
  ok(proof)

{.pop.}
