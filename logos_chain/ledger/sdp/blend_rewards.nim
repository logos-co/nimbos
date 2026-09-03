# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Blend reward pipeline: income accumulation, activity-proof verification
## against the frozen target epoch, and payout at rotation.
## Spec: [Service Reward Distribution](https://github.com/logos-co/logos-lips/blob/a2a85cbe444e9727ae7f42b2f6d6f4c6bf8d63e9/docs/blockchain/raw/bedrock-service-reward-distribution.md),
## [Blend Protocol](https://github.com/logos-co/logos-lips/blob/a2a85cbe444e9727ae7f42b2f6d6f4c6bf8d63e9/docs/blockchain/raw/blend-protocol.md)
## §Proof of Selection, §Rewarding.

{.push raises: [], gcsafe.}

import
  std/[algorithm, sequtils, tables],
  results,
  stew/endians2,
  ../types,
  ../poq_verifier,
  ./[blend_token, rewards],
  ../../core/crypto/hashing,
  ../../core/mantle/primitives,
  ../../core/mantle/utxo,
  ../../utils/hash_trie_map

export blend_token, hash_trie_map, poq_verifier

type
  TargetEpoch = object
    epoch*: EpochNumber
    providers*: HashTrieMap[ProviderId, tuple[zkId: ZkPublicKey, index: uint64]]
    tokenParams*: TokenParams
    randomnessDigest*: array[8, byte]
      ## ``H(R)_e``, hashed once at rotation; valid prefix = tokenParams.byteLen
    epochIncome*: Value
    poqPublic*: PoqPublic
      ## Public inputs every activity proof for this epoch verifies
      ## against. Frozen at rotation from the epoch's own chain values.

  SubmissionTracker = object
    submitted*: HashTrieMap[ProviderId, tuple[zkId: ZkPublicKey, distance: uint64]]
      ## One entry per provider; the premium set derives from the
      ## distances at payout, so no second representation can drift.

  BlendRewardsParams* = object
    roundsPerEpoch*: uint64
    messageFrequencyPerRound*: float64
    numBlendLayers*: uint64
    dataReplicationFactor*: uint64
      # The data-message redundancy R_D of the leadership quota, not the
      # cover redundancy R_C of the core quota; the quota verifier needs it.
    minimumNetworkSize*: uint64
    activityThresholdSensitivity*: uint64

  BlendRewards* = object
    target*: Opt[tuple[state: TargetEpoch, tracker: SubmissionTracker]]
    epochIncome*: Value ## current epoch's accumulator

const SelectionDomainTag = "BlendNode"

let KeyNullifierDomainFr*: FieldElement =
  # DST for deriving the proof-of-quota key nullifier from the secret
  # selection randomness (spec §Proof of Selection, condition 2).
  frFromBytesLE("KEY_NULLIFIER_V1".toOpenArrayByte(0, 15)).get

# The quota circuit compares 20-bit integers. A quota at or past this
# bound admits no proof, so it is a parameter bug, not a proof property.
const MaxCircuitQuota = 1'u64 shl 20

func leaderQuota(params: BlendRewardsParams): uint64 =
  ## Blending operations one election win buys: `Q_L = beta * (1 + R_D)`.
  params.numBlendLayers * (1 + params.dataReplicationFactor)

func validateBlendRewardsParams*(params: BlendRewardsParams) =
  ## The token evaluation needs a positive expected message count and a
  ## nonzero network floor (spec parameter validity, ``C * beta_C > 0``).
  # A zero here reaches a zero digest width, which BLAKE2b cannot produce;
  # failing at init beats a degenerate lottery at an epoch boundary.
  doAssert params.roundsPerEpoch > 0, "rounds_per_epoch must be positive"
  doAssert params.messageFrequencyPerRound > 0.0,
    "message_frequency_per_round must be positive"
  doAssert params.numBlendLayers > 0, "num_blend_layers must be positive"
  doAssert params.minimumNetworkSize > 0,
    "minimum_network_size must be positive"
  doAssert float64(params.roundsPerEpoch) * params.messageFrequencyPerRound *
      float64(params.numBlendLayers) > 0.0,
    "C * beta_C must be positive"
  doAssert params.dataReplicationFactor <=
      (high(uint64) div params.numBlendLayers) - 1,
    "leadership quota overflows uint64"
  doAssert leaderQuota(params) < MaxCircuitQuota,
    "leadership quota exceeds the circuit's 20-bit width"

func initSubmissionTracker(): SubmissionTracker =
  SubmissionTracker(
    submitted:
      HashTrieMap[ProviderId, tuple[zkId: ZkPublicKey, distance: uint64]].init())

func addIncome*(
    r: sink BlendRewards, income: Value
): Result[BlendRewards, LedgerError] =
  ## Accrues one block's blend share into the current epoch.
  if r.epochIncome > high(Value) - income:
    return err(BalanceOutOfRange)
  r.epochIncome += income
  ok(r)

func expectedSelectionIndex*(
    selectionRandomness: FieldElement, membershipSize: uint64
): uint64 =
  ## ``CSPRNG(H_N(rho))_8 mod N`` (spec §Proof of Selection, condition 1).
  const TagLen = SelectionDomainTag.len
  var seedInput {.noinit.}: array[TagLen + 32, byte]
  seedInput[0 ..< TagLen] =
    SelectionDomainTag.toOpenArrayByte(0, SelectionDomainTag.high)
  seedInput[TagLen ..< TagLen + 32] = encodeFieldElement(selectionRandomness)
  let stream = prngBlock(blake2b512Hash(seedInput), 0)
  uint64.fromBytesLE(stream.toOpenArray(0, 7)) mod membershipSize

proc verifyActivity(
    state: TargetEpoch,
    tracker: SubmissionTracker,
    proof: ActivityProof,
    providerId: ProviderId,
    verifyPoq: ProofOfQuotaVerifier,
): Result[tuple[zkId: ZkPublicKey, distance: uint64], LedgerError] =
  if proof.epoch != state.epoch:
    return err(InvalidEpoch)
  # One map probe; checking it first keeps a resubmission from buying
  # the whole proof pipeline.
  if providerId in tracker.submitted:
    return err(DuplicateActiveMessage)
  let provider = state.providers.get(providerId).valueOr:
    return err(UnknownProvider)
  let quotaProofHolds = verifyPoq(
      proof.proofOfQuota, proof.signingKey, state.poqPublic).valueOr:
    return err(VerifierNotInitialised)
  if not quotaProofHolds:
    return err(InvalidTxProof)
  let membership = uint64(state.providers.len)
  if expectedSelectionIndex(proof.proofOfSelection, membership) !=
      provider.index:
    return err(InvalidTxProof)
  if Poseidon2Hasher.compress(KeyNullifierDomainFr, proof.proofOfSelection) !=
      proof.proofOfQuota.keyNullifier:
    return err(InvalidTxProof)
  let
    token = BlendingToken(
      signingKey: proof.signingKey,
      proofOfQuota: proof.proofOfQuota,
      selectionRandomness: proof.proofOfSelection)
    distance = hammingDistance(
      token, state.randomnessDigest, state.tokenParams.byteLen)
  if distance > state.tokenParams.threshold:
    return err(HammingDistanceTooLarge)
  ok((provider.zkId, distance))

proc recordActivity*(
    r: sink BlendRewards,
    proof: ActivityProof,
    providerId: ProviderId,
    verifyPoq: ProofOfQuotaVerifier,
): Result[BlendRewards, LedgerError] =
  ## Verifies one SDP Active submission for the target epoch and records
  ## its Hamming distance; any error invalidates the transaction.
  if r.target.isNone:
    return err(TargetEpochNotSet)
  # In-place update: the state half is unchanged, so no repacked tuple.
  let accepted = ?verifyActivity(
    r.target.get.state, r.target.get.tracker, proof, providerId, verifyPoq)
  r.target.get.tracker.submitted = r.target.get.tracker.submitted.insert(
    providerId, (accepted.zkId, accepted.distance))
  ok(r)

func payout(state: TargetEpoch, tracker: SubmissionTracker): seq[Utxo] =
  ## Base reward ``income div (B + P)``, premium doubled, zero rewards and
  ## the division remainder never minted (spec §Distribution).
  if tracker.submitted.len == 0:
    return @[]
  var
    minDistance = high(uint64)
    premiums = 0'u64
  for entry in tracker.submitted.values:
    if entry.distance < minDistance:
      minDistance = entry.distance
      premiums = 1
    elif entry.distance == minDistance:
      inc premiums
  # The divisor counts premium providers twice. A non-empty premium set
  # therefore gives base * 2 <= income, so the doubling cannot overflow.
  let base = state.epochIncome div (uint64(tracker.submitted.len) + premiums)
  var rewards: Table[ZkPublicKey, Value]
  for entry in tracker.submitted.values:
    # Declare validation rejects a zk_id already used in the service, so
    # payout entries never collide.
    doAssert entry.zkId notin rewards, "duplicate zk_id in payout set"
    rewards[entry.zkId] =
      if entry.distance == minDistance: base * 2 else: base
  distributeRewards(rewards, state.epoch, ServiceType.bn)

func cmpSnapshotEntry(
    x, y: tuple[providerId: ProviderId, zkId: ZkPublicKey]
): int =
  cmpNumeric(x.zkId, y.zkId)

func rotateEpoch*(
    r: sink BlendRewards,
    prevEpoch, newEpoch: EpochNumber,
    snapshot: openArray[tuple[providerId: ProviderId, zkId: ZkPublicKey]],
    epochRandomness: FieldElement,
    params: BlendRewardsParams,
    poqChain: PoqChainContext,
): tuple[rewards: BlendRewards, minted: seq[Utxo]] =
  ## Pays out the frozen target and freezes the finished epoch as the new
  ## target. When no target can form, the finished epoch forfeits its income.
  # `poqChain` carries the finished epoch's frozen chain values. The
  # target's activity proofs were generated against them.
  doAssert newEpoch > prevEpoch, "epoch rotation must advance"
  var minted: seq[Utxo]
  if r.target.isSome:
    let (state, tracker) = r.target.get
    minted = payout(state, tracker)
  var next = BlendRewards()
  # The quota math divides by the provider count, so an empty set never
  # forms a target.
  let providerCount = uint64(snapshot.len)
  if newEpoch == prevEpoch + 1 and snapshot.len > 0 and
      providerCount >= params.minimumNetworkSize:
    var byZkId = @snapshot
    byZkId.sort(cmpSnapshotEntry)
    let zkIds = byZkId.mapIt(it.zkId)
    var providers =
      HashTrieMap[ProviderId, tuple[zkId: ZkPublicKey, index: uint64]].init()
    for i, entry in byZkId:
      providers = providers.insert(
        entry.providerId, (entry.zkId, uint64(i)))
    # No integer represents this quota, so no proof can be evaluated;
    # forfeit like an undersized network instead of halting the node.
    let quota = coreQuota(
        params.roundsPerEpoch, params.messageFrequencyPerRound,
        params.numBlendLayers, providerCount).valueOr:
      return (next, minted)

    let
      evaluation = tokenParams(
        quota, providerCount, params.activityThresholdSensitivity).valueOr:
        return (next, minted)
      coreRoot = coreZkIdRoot(zkIds).valueOr:
        return (next, minted)
    next.target = Opt.some((
      TargetEpoch(
        epoch: prevEpoch,
        providers: providers,
        tokenParams: evaluation,
        randomnessDigest: randomnessDigest(
          epochRandomness, evaluation.byteLen),
        epochIncome: r.epochIncome,
        poqPublic: PoqPublic(
          coreQuota: quota,
          leaderQuota: leaderQuota(params),
          powQuota: params.numBlendLayers,
          coreRoot: coreRoot,
          chain: poqChain)),
      initSubmissionTracker()))
  (next, minted)

{.pop.}
