# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Leader reward pool + global voucher Merkle tree for `LeaderClaim` ops.
##
## Spec: [Anonymous Leaders Reward Protocol v1.0.0](https://nomos-tech.notion.site/1-0-0-Anonymous-Leaders-Reward-Protocol-206261aa09df8120a49ffa49c71ba70d#240261aa09df80de83eace3d556eddfc)
##
## One Merkle tree of voucher commitments spans the full chain. On the **first
## block of each new epoch**, ``addEpochVouchers`` appends the departing epoch's
## commitments and rolls its rewards into ``leadersRewards``. Until the next
## epoch start, ``voucherTree`` / ``voucherCmSetSize`` stay fixed while claims
## spend nullifiers and debit the pool.

{.push raises: [], gcsafe.}

import
  results,
  ../core/mantle/primitives,
  ../utils/dynamic_merkle_tree,
  ../zk/poseidon2/hasher,
  ./types

export primitives, results, types

type
  VoucherMerkleTree* = DynamicMerkleTree[RewardVoucher, Poseidon2Hasher]

func asField*(voucher: RewardVoucher): FieldElement =
  frFromBytesLEModOrder(voucher)

type LeaderState* = object
  voucherTree*: VoucherMerkleTree
  voucherCmSetSize*: uint64
  spentNullifiers*: seq[VoucherNullifier]
  leadersRewards*: Value

func init*(_: typedesc[LeaderState]): LeaderState =
  let tree = VoucherMerkleTree.init()
  LeaderState(
    voucherTree: tree,
    voucherCmSetSize: 0,
    spentNullifiers: @[],
    leadersRewards: 0,
  )

func rewardShare*(s: LeaderState): Value =
  ## Per-voucher reward share (spec Leaders Reward):
  ##
  ## .. math::
  ##   share = 0                         if |voucher_cm| = |voucher_nf|
  ##   share = leaders_rewards / (|voucher_cm| - |voucher_nf|)  otherwise
  ##
  ## Stable within an epoch: each claim debits ``leadersRewards`` and adds one
  ## to ``|voucher_nf|``, so the quotient is unchanged when division is exact.
  let
    nCm = s.voucherCmSetSize
    nNf = uint64(s.spentNullifiers.len)
  if nCm == nNf:
    0'u64
  else:
    s.leadersRewards div (nCm - nNf)

func addEpochVouchers*(
    s: sink LeaderState,
    vouchers: openArray[RewardVoucher],
    lastEpochRewards: Value,
): LeaderState =
  ## TODO: wire from ``tryApplyHeader`` once epoch management lands.
  s.voucherTree = s.voucherTree.insert(vouchers)
  s.voucherCmSetSize += uint64(vouchers.len)
  s.leadersRewards += lastEpochRewards
  s

func tryRecordClaim*(
    s: sink LeaderState, nf: VoucherNullifier
): Result[tuple[state: LeaderState, reward: Value], LedgerError] =
  ## Compute per-voucher reward, validate the pool, then record the claim.
  let reward = s.rewardShare()
  if reward == 0:
    return err(NoClaimableReward)
  if reward > s.leadersRewards:
    return err(BalanceOverflow)
  s.spentNullifiers.add(nf)
  s.leadersRewards -= reward
  ok((state: s, reward: reward))

func `==`*(a, b: LeaderState): bool =
  a.voucherTree == b.voucherTree and
    a.voucherCmSetSize == b.voucherCmSetSize and
    a.spentNullifiers == b.spentNullifiers and
    a.leadersRewards == b.leadersRewards

{.pop.}
