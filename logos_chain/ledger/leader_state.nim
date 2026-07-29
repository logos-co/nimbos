# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Leader reward pool + global voucher Merkle tree for `LeaderClaim` ops.
##
## Spec: [Anonymous Leaders Reward Protocol v1.0.0](https://github.com/logos-co/logos-lips/blob/b7602ed8a225d41ca0bfaaa432524dc84d2ded7e/docs/blockchain/raw/bedrock-anonymous-leaders-reward.md)
##
## One Merkle tree of voucher commitments spans the full chain. On the **first
## block of each new epoch**, ``addEpochVouchers`` appends the departing epoch's
## commitments and rolls its rewards into ``leadersRewards``. Until the next
## epoch start, ``voucherTree`` / ``voucherCmSetSize`` stay fixed while claims
## spend nullifiers and debit the pool.

{.push raises: [], gcsafe.}

import
  ../utils/hash_trie_map,
  intops,
  results,
  ../core/mantle/[primitives, operations, proofs],
  ../utils/dynamic_merkle_tree,
  ../zk/poseidon2/hasher,
  ./types,
  ./poc_verifier

export primitives, results, types

type
  VoucherMerkleTree = DynamicMerkleTree[RewardVoucher, Poseidon2Hasher]

func asField*(voucher: RewardVoucher): FieldElement =
  frFromBytesLEModOrder(voucher)

type LeaderPending = object
  vouchers: seq[RewardVoucher]
  reward: Value

type LeaderState* = object
  voucherTree: VoucherMerkleTree
  spentNullifiers: HashTrieMap[VoucherNullifier, tuple[]]
  leadersRewards: Value
  pending: LeaderPending

func init*(_: typedesc[LeaderState]): LeaderState =
  let tree = VoucherMerkleTree.init()
  LeaderState(
    voucherTree: tree,
    spentNullifiers: HashTrieMap[VoucherNullifier, tuple[]].init(),
    leadersRewards: 0,
    pending: LeaderPending(vouchers: @[], reward: 0),
  )

func voucherTree*(s: LeaderState): lent VoucherMerkleTree =
  s.voucherTree

func leadersRewards*(s: LeaderState): Value =
  s.leadersRewards

func contains*(s: LeaderState, nf: VoucherNullifier): bool =
  nf in s.spentNullifiers

func rewardShare*(s: LeaderState): Value =
  ## Per-voucher reward share (spec Leaders Reward), using integer division:
  ##
  ## .. math::
  ##   share = 0                                      if |voucher_cm| = |voucher_nf|
  ##   share = \lfloor leaders\_rewards / n \rfloor   otherwise
  ##
  ## where ``n = |voucher_cm| - |voucher_nf|``. While ``leadersRewards = share * n``,
  ## each claim keeps the same floor share. When the pool is not evenly divisible,
  ## early claims take ``\lfloor R/n \rfloor`` and the final claim(s) receive a
  ## larger residual (e.g. 100 / 3 → 33, 33, 34).
  let
    nCm = uint64(s.voucherTree.len())
    nNf = uint64(s.spentNullifiers.len)
  if nCm == nNf:
    0'u64
  else:
    s.leadersRewards div (nCm - nNf)

func recordBlockLeader*(
    s: sink LeaderState,
    voucher: RewardVoucher,
    reward: Value,
): LeaderState =
  s.pending.vouchers.add(voucher)
  s.pending.reward += reward
  s

func addEpochVouchers*(
    s: sink LeaderState,
): Result[LeaderState, LedgerError] =
  ## Note: This function is only called when a new epoch starts.
  s.voucherTree = s.voucherTree.insert(s.pending.vouchers)
  let (res, didOverflow) = overflowingAdd(s.leadersRewards, s.pending.reward)
  if didOverflow:
    return err(BalanceOverflow)
  s.leadersRewards = res
  s.pending.vouchers = @[]
  s.pending.reward = 0
  ok(s)

func recordClaim(
    s: sink LeaderState, nf: VoucherNullifier
): tuple[state: LeaderState, reward: Value] =
  let reward = s.rewardShare()
  s.spentNullifiers = s.spentNullifiers.insert(nf, ())
  s.leadersRewards -= reward
  (state: s, reward: reward)

proc tryRecordClaim*(
    s: sink LeaderState,
    op: LeaderClaimPayload,
    proof: ProofOfClaimProof,
    txHash: ZkHash,
    verifyProof: ProofOfClaimVerifier = verifyProofOfClaim,
): Result[tuple[state: LeaderState, reward: Value], LedgerError] =
  if op.voucherNullifier in s:
    return err(DuplicatedVoucherNullifier)
  let rewardsRoot = root(s.voucherTree)
  if op.rewardsRoot != rewardsRoot:
    return err(RewardsRootMismatch)

  let public = proofOfClaimPublic(op, rewardsRoot, txHash)
  let verified = verifyProof(proof, public).valueOr:
    return err(VerifierNotInitialised)
  if not verified:
    return err(InvalidProof)

  ok(s.recordClaim(op.voucherNullifier))

func `==`*(a, b: LeaderState): bool =
  a.voucherTree == b.voucherTree and
    a.spentNullifiers == b.spentNullifiers and
    a.leadersRewards == b.leadersRewards and
    a.pending.vouchers == b.pending.vouchers and
    a.pending.reward == b.pending.reward

{.pop.}
