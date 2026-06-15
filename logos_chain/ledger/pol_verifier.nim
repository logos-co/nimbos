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
  ../core/types,
  ../core/crypto/types,
  ../core/mantle/primitives,
  ../zk/pol

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

func isGenesisLeaderProof(p: ProofOfLeadership): bool =
  p.proof == DefaultCompressedGroth16Proof and
    p.entropyContribution == static(default(ZkHash)) and
    encodeEd25519PublicKey(p.leaderKey) == default(array[32, byte]) and
    p.leaderVoucher == static(default(RewardVoucher))

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
