# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## ZkSig proof verification against the mantle tx hash.

{.push raises: [], gcsafe.}

import
  results,
  ./types,
  ../core/[crypto/types, mantle/proofs],
  ../zk/[poseidon2/hasher, zksign]

proc verifyZkSig*(
    proof: ZkSigProof,
    txHash: Hash32,
    publicKeys: openArray[ZkPublicKey],
): Result[void, LedgerError] =
  ## Verifies a ZkSig over ``publicKeys`` and ``txHash``. The hash is reduced
  ## mod the BN254 field order so prover and verifier agree on the signed Fr.
  let msgFr = frFromBytesLEModOrder(txHash)
  let input = zksignInput(publicKeys, msgFr).valueOr:
    return err(InvalidProof)
  let verified = zksign.verify(proof, input).valueOr:
    return err(VerifierNotInitialised)
  if not verified:
    return err(InvalidProof)
  ok()

{.pop.}
