# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## PoC ledger seam: `ProofOfClaimPublic` + `verifyProofOfClaim` bridging mantle
## types to `poc.verify` (which holds the singleton VK).

{.push raises: [], gcsafe.}

import
  results,
  ../core/mantle/[operations, proofs],
  ../core/crypto/types,
  ../zk/poc,
  ../zk/poseidon2/hasher

export poc, results

func proofOfClaimPublic*(
    op: LeaderClaimPayload,
    rewardsRoot: RewardsRoot,
    txHash: ZkHash,
): ProofOfClaimPublic =
  ## Assemble mantle `ProofOfClaimPublic` for Groth16 verify. `rewardsRoot`
  ## is the ledger snapshot (must match `op.rewardsRoot` before calling).
  ProofOfClaimPublic(
    voucherNullifier: encodeFieldElement(op.voucherNullifier),
    voucherRoot: encodeFieldElement(rewardsRoot),
    mantleTxHash: encodeFieldElement(frFromBytesLEModOrder(txHash)),
  )

proc verifyProofOfClaim*(
    proof: ProofOfClaimProof, public: ProofOfClaimPublic
): Result[bool, PocLoadError] =
  ## Out-of-modulus public hashes return `ok(false)`. `err(VkNotLoaded)` only
  ## on missing startup init.
  let voucherNullifier = frFromBytesLE(public.voucherNullifier).valueOr:
    return ok(false)
  let mantleTxHashFr = frFromBytesLE(public.mantleTxHash).valueOr:
    return ok(false)
  let voucherRoot = frFromBytesLE(public.voucherRoot).valueOr:
    return ok(false)
  poc.verify(proof, PocVerifierInput(
    voucherNullifier: voucherNullifier,
    mantleTxHashFr: mantleTxHashFr,
    voucherRoot: voucherRoot,
  ))

{.pop.}
