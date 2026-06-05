# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## PoL ledger seam: `LeaderPublic` shape + `verifyLeaderProof` that bridges
## wire types to `pol.verify` (which holds the singleton VK).

{.push raises: [], gcsafe.}

import
  stew/endians2,
  ../core/types,
  ../core/crypto/types,
  ../core/mantle/primitives,
  ../zk/pol,
  ../zk/poseidon2/hasher

export pol

type
  LeaderPublic* = object
    ## Header-level public inputs assembled by the cryptarchia layer.
    slot*: SlotNumber
    epochNonce*: FieldElement
    lottery0*: FieldElement
    lottery1*: FieldElement
    agedRoot*: FieldElement
    latestRoot*: FieldElement

func slotToFr(slot: SlotNumber): FieldElement =
  # uint64 → 8 LE bytes; `frFromBytesLE` zero-pads to 32. No signed-int hop.
  frFromBytesLE(uint64(slot).toBytesLE()).get

func ed25519PkToFrPair(pk: Ed25519PublicKey): (FieldElement, FieldElement) =
  # Split a 32-byte ed25519 key into two 16-byte halves; each fits in BN254.
  let raw = encodeEd25519PublicKey(pk)
  (
    frFromBytesLE(raw.toOpenArray(0, 15)).get,
    frFromBytesLE(raw.toOpenArray(16, 31)).get,
  )

func isGenesisLeaderProof(p: ProofOfLeadership): bool =
  p.proof == DefaultCompressedGroth16Proof and
    p.entropyContribution == default(ZkHash) and
    encodeEd25519PublicKey(p.leaderKey) == default(array[32, byte]) and
    p.leaderVoucher == default(RewardVoucher)

proc verifyLeaderProof*(
    proof: ProofOfLeadership, public: LeaderPublic): Result[bool, PolLoadError] =
  ## Genesis sentinel short-circuits to `ok(true)`. Out-of-modulus entropy
  ## bytes return `ok(false)`. `err(VkNotLoaded)` only on missing startup init.
  if isGenesisLeaderProof(proof):
    return ok(true)

  let entropyFr = frFromBytesLE(proof.entropyContribution).valueOr:
    return ok(false)

  let
    (pk1, pk2) = ed25519PkToFrPair(proof.leaderKey)
    input = PolVerifierInput(
      entropyContribution: entropyFr,
      slotNumber: slotToFr(public.slot),
      epochNonce: public.epochNonce,
      lottery0: public.lottery0,
      lottery1: public.lottery1,
      agedRoot: public.agedRoot,
      latestRoot: public.latestRoot,
      leaderPk1: pk1,
      leaderPk2: pk2,
    )
  pol.verify(proof.proof, input)

{.pop.}
