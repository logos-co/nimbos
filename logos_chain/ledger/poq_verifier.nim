# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## PoQ ledger seam: `PoqPublic` + `verifyProofOfQuota` bridging mantle
## types to `poq.verify`, plus the core-node zk-id Merkle root.

{.push raises: [], gcsafe.}

import
  std/algorithm,
  results,
  stew/endians2,
  ../core/mantle/blend_activity,
  ../core/crypto/types,
  ../zk/poq,
  ../zk/poseidon2/hasher,
  ../utils/dynamic_merkle_tree

export poq, results

const CORE_MERKLE_TREE_HEIGHT = 20
  ## Depth of the core-node zk-id registry tree, up to 2^20 members.

type
  PoqChainContext* = object
    ## The epoch-frozen chain half of the PoQ public inputs. Captured from
    ## the epoch the proofs target, not the epoch that receives them.
    polLedgerAged*: FieldElement
    polEpochNonce*: FieldElement
    lottery0*: FieldElement
    lottery1*: FieldElement
    powBlendDifficulty*: FieldElement

  PoqPublic* = object
    ## Epoch context for proof-of-quota verification, minus the
    ## per-message signing key.
    coreQuota*: uint64
    leaderQuota*: uint64
    powQuota*: uint64
    coreRoot*: FieldElement
    chain*: PoqChainContext

  ProofOfQuotaVerifier* = proc(
    proofOfQuota: ProofOfQuota, signingKey: Ed25519PublicKey,
    public: PoqPublic
  ): Result[bool, PoqLoadError] {.gcsafe, raises: [].}

func quotaToFr(quota: uint64): FieldElement =
  frFromBytesLE(quota.toBytesLE()).expect("8 bytes < order")

func coreZkIdRoot*(
    zkIds: openArray[ZkPublicKey]
): Result[FieldElement, cstring] =
  ## Root of the fixed-depth registry tree.
  # Members sort ascending by numeric value. Empty leaves are zero and
  # follow the members. Nodes use Poseidon2 compression.
  if zkIds.len == 0:
    return err(cstring"core zk-id set is empty")
  if zkIds.len > 1 shl CORE_MERKLE_TREE_HEIGHT:
    return err(cstring"core zk-id set exceeds tree capacity")
  var level = @zkIds
  level.sort(cmpNumeric)
  for i in 1 ..< level.len:
    if level[i - 1] == level[i]:
      return err(cstring"duplicate core zk-id")
  # Each level keeps only the populated prefix. Every sibling to the
  # right of it is the empty-subtree root for that height. The cache
  # behind `getEmptyRoots` fills once and is read-only after.
  let emptyRoots = block:
    {.cast(noSideEffect).}:
      Poseidon2Hasher.getEmptyRoots()
  for height in 0 ..< CORE_MERKLE_TREE_HEIGHT:
    let parents = (level.len + 1) div 2
    for i in 0 ..< parents:
      let right =
        if 2 * i + 1 < level.len: level[2 * i + 1]
        else: emptyRoots[height]
      level[i] = Poseidon2Hasher.compress(level[2 * i], right)
    level.setLen(parents)
  ok(level[0])

proc verifyProofOfQuota*(
    proofOfQuota: ProofOfQuota, signingKey: Ed25519PublicKey,
    public: PoqPublic
): Result[bool, PoqLoadError] =
  ## `err(VkNotLoaded)` only on missing startup init. Every proof-shaped
  ## failure is `ok(false)`.
  let (kPartOne, kPartTwo) = ed25519PkToFrPair(signingKey)
  verify(
    proofOfQuota.proof,
    PoqVerifierInput(
      keyNullifier: proofOfQuota.keyNullifier,
      coreQuota: quotaToFr(public.coreQuota),
      leaderQuota: quotaToFr(public.leaderQuota),
      coreRoot: public.coreRoot,
      powQuota: quotaToFr(public.powQuota),
      polLedgerAged: public.chain.polLedgerAged,
      kPartOne: kPartOne,
      kPartTwo: kPartTwo,
      powBlendDifficulty: public.chain.powBlendDifficulty,
      polEpochNonce: public.chain.polEpochNonce,
      polT0: public.chain.lottery0,
      polT1: public.chain.lottery1,
    ),
  )

{.pop.}
