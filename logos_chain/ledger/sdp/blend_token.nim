# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Blend token evaluation: core quota, activity threshold and the Hamming
## lottery over blending tokens.
## Spec: [Blend Protocol](https://github.com/logos-co/logos-lips/blob/a2a85cbe444e9727ae7f42b2f6d6f4c6bf8d63e9/docs/blockchain/raw/blend-protocol.md)
## §Core Quota, §Activity Proof, §Activity Threshold; quota ceil-rounding,
## threshold clamp and inclusive comparison per the pending 1.2.0 revision
## (logos-lips#405).

{.push raises: [], gcsafe.}

import
  std/math,
  results,
  stew/bitops2,
  ../../core/crypto/hashing,
  ../../core/mantle/blend_activity

export blend_activity

const BlendingTokenLen = ActivityProofBodyLen

type
  TokenParams* = object
    byteLen*: uint64 ## digest width in bytes, ``ceil(bit_len / 8)``
    threshold*: uint64 ## activity threshold ``A_e``, saturated at zero

  BlendingToken* = object
    signingKey*: Ed25519PublicKey
    proofOfQuota*: ProofOfQuota
    selectionRandomness*: FieldElement

func bitLength(n: uint64): uint64 =
  ## ``ceil(log2(n + 1))``, exact for every uint64.
  if n == 0: 0'u64 else: 64'u64 - uint64(leadingZeros(n))

func coreQuota*(
    roundsPerEpoch: uint64,
    messageFrequencyPerRound: float64,
    numBlendLayers, membershipSize: uint64,
): Result[uint64, cstring] =
  ## ``Q_C = ceil(C * beta_C / N)`` with ``C = E * F_C`` and ``R_C = 0``
  ## (spec §Core Quota; ceil rounding per the pending 1.2.0 revision).
  # IEEE mul, div and ceil round correctly, so this float chain is
  # deterministic across platforms. The log2 steps below stay integer.
  let
    expectedEpochMessages =
      float64(roundsPerEpoch) * messageFrequencyPerRound
    quota = ceil(
      expectedEpochMessages * float64(numBlendLayers) /
      float64(membershipSize))
  # Outside ``[0, 2^64)`` the uint64 conversion is undefined; NaN fails
  # every ordered comparison, so the first test also rejects it.
  if not (quota >= 0.0):
    return err("core quota: not a number")
  if quota >= 1.8446744073709552e19:
    return err("core quota: exceeds uint64")
  ok(uint64(quota))

func tokenParams*(
    coreQuota, numProviders, sensitivity: uint64
): Result[TokenParams, cstring] =
  ## Digest width and activity threshold ``max(0, chi - nu - theta)`` for one
  ## target epoch (spec §Activity Threshold).
  if numProviders == high(uint64):
    return err("token params: network size too large")
  if coreQuota != 0 and numProviders > high(uint64) div coreQuota:
    return err("token params: total core quota overflows")
  let
    tokenCountBitLen = bitLength(coreQuota * numProviders)
    networkSizeBitLen = bitLength(numProviders)
    belowNetwork = tokenCountBitLen - min(tokenCountBitLen, networkSizeBitLen)
  ok(TokenParams(
    byteLen: (tokenCountBitLen + 7) div 8,
    threshold: belowNetwork - min(belowNetwork, sensitivity)))

func toBytes(token: BlendingToken): array[BlendingTokenLen, byte] =
  ## Token hash preimage, shared with the wire codec.
  encodeActivityProofBody(
    token.signingKey, token.proofOfQuota, token.selectionRandomness)

func randomnessDigest*(
    epochRandomness: FieldElement, byteLen: uint64
): array[8, byte] =
  ## ``H(R)_e`` — the epoch-randomness digest the lottery compares against.
  blake2bShort(encodeFieldElement(epochRandomness), byteLen)

func hammingDistance*(
    token: BlendingToken, randomnessDigest: array[8, byte], byteLen: uint64
): uint64 =
  ## ``delta_H(H(t)_e, H(R)_e)`` — differing bits between the token digest
  ## and the precomputed epoch-randomness digest (spec §Activity Proof).
  let tokenHash = blake2bShort(toBytes(token), byteLen)
  var distance = 0'u64
  for i in 0 ..< int(byteLen):
    distance += uint64(countOnes(tokenHash[i] xor randomnessDigest[i]))
  distance

{.pop.}
