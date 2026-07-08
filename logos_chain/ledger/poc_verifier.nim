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
  ../core/mantle/proofs,
  ../zk/poc,
  ../zk/poseidon2/hasher

export poc, results

proc verifyProofOfClaim*(
    proof: ProofOfClaimProof, public: ProofOfClaimPublic
): Result[bool, PocLoadError] =
  poc.verify(proof, PocVerifierInput(
    voucherNullifier: frFromBytesLE(public.voucherNullifier).get,
    mantleTxHashFr: frFromBytesLE(public.mantleTxHash).get,
    voucherRoot: frFromBytesLE(public.voucherRoot).get,
  ))

{.pop.}
