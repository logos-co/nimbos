# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/[json, os, strutils],
  unittest2,
  stew/[endians2, io2],
  libp2p/crypto/ed25519/ed25519,
  ../../logos_chain/ledger/sdp/blend_rewards,
  ../../logos_chain/zk/groth16/utils,
  ../../logos_chain/core/mantle/blend_activity,
  ./sdp/test_helpers,
  ../zk/snarkjs_helpers

from ../../logos_chain/zk/poq as zk_poq import nil

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  fixtureDir = testsDir / "../fixtures/poq"
  fixtureVk = fixtureDir / "verification_key.json"

type PoqFixture = object
  proofOfQuota: ProofOfQuota
  signingKey: Ed25519PublicKey
  public: PoqPublic
  signals: seq[FieldElement]

func frToUint64(value: FieldElement): uint64 =
  # Quota signals fit 20 bits. The low 8 little-endian bytes carry them.
  uint64.fromBytesLE(encodeFieldElement(value).toOpenArray(0, 7))

proc loadFixture(tag: string): PoqFixture =
  ## Reconstruct the wire proof and the verifier context from one
  ## committed fixture, inverting the seam's own input assembly.
  let
    bin = io2.readAllBytes(fixtureDir / ("proof_" & tag & ".bin")).expect(
      "fixture bin readable")
    publicText = readAllChars(fixtureDir / ("public_" & tag & ".json")).expect(
      "fixture public readable")
    signals = publicJsonToInputs(publicText).expect("fixture public parses")
  doAssert bin.len == 160 and signals.len == 12
  var
    proof: CompressedGroth16Proof
    keyBytes: array[32, byte]
  proof[0 ..< 128] = bin.toOpenArray(32, bin.high)
  # The signing key is the little-endian bytes of the two 16-byte halves.
  keyBytes[0 ..< 16] = encodeFieldElement(signals[6]).toOpenArray(0, 15)
  keyBytes[16 ..< 32] = encodeFieldElement(signals[7]).toOpenArray(0, 15)
  var signingKey: Ed25519PublicKey
  doAssert signingKey.init(keyBytes)
  PoqFixture(
    proofOfQuota: ProofOfQuota(
      keyNullifier: frFromBytesLE(bin.toOpenArray(0, 31)).expect("canonical"),
      proof: proof),
    signingKey: signingKey,
    public: PoqPublic(
      coreQuota: frToUint64(signals[1]),
      leaderQuota: frToUint64(signals[2]),
      powQuota: frToUint64(signals[4]),
      coreRoot: signals[3],
      chain: PoqChainContext(
        polLedgerAged: signals[5],
        polEpochNonce: signals[9],
        lottery0: signals[10],
        lottery1: signals[11],
        powBlendDifficulty: signals[8])),
    signals: signals)

proc installFixtureVk(): bool =
  zk_poq.resetVkForTesting()
  let
    vkText = readAllChars(fixtureVk).valueOr:
      return false
    vk = parseVk(vkText).valueOr:
      return false
  zk_poq.initVk(vk).isOk

suite "ledger/poq_verifier — verifyProofOfQuota":
  setup:
    check installFixtureVk()
    let fixture = loadFixture("core")

  test "accepts a wire fixture with reconstructed context":
    let r = verifyProofOfQuota(
      fixture.proofOfQuota, fixture.signingKey, fixture.public)
    check r.isOk and r.get

  test "VkNotLoaded without startup init":
    zk_poq.resetVkForTesting()
    check verifyProofOfQuota(
      fixture.proofOfQuota, fixture.signingKey, fixture.public
    ).error == VkNotLoaded

  test "rejects a wrong signing key — the key halves are bound":
    var keyBytes: array[32, byte]
    keyBytes[0] = 0xC8
    var wrongKey: Ed25519PublicKey
    check wrongKey.init(keyBytes)
    let r = verifyProofOfQuota(fixture.proofOfQuota, wrongKey, fixture.public)
    check r.isOk and not r.get

  test "rejects every mutated context field":
    let other = frFromBytesLE([byte 0xEE]).get
    for field in 0 ..< 9:
      var bad = fixture.public
      case field
      of 0: bad.coreQuota = bad.coreQuota + 1
      of 1: bad.leaderQuota = bad.leaderQuota + 1
      of 2: bad.powQuota = bad.powQuota + 1
      of 3: bad.coreRoot = other
      of 4: bad.chain.polLedgerAged = other
      of 5: bad.chain.polEpochNonce = other
      of 6: bad.chain.lottery0 = other
      of 7: bad.chain.lottery1 = other
      else: bad.chain.powBlendDifficulty = other
      let r = verifyProofOfQuota(fixture.proofOfQuota, fixture.signingKey, bad)
      check r.isOk and not r.get

  test "rejects a mutated key nullifier":
    var bad = fixture.proofOfQuota
    bad.keyNullifier = frFromBytesLE([byte 0xEE]).get
    let r = verifyProofOfQuota(bad, fixture.signingKey, fixture.public)
    check r.isOk and not r.get

suite "ledger/poq_verifier — coreZkIdRoot":
  test "empty set is an error":
    check coreZkIdRoot([]).isErr

  test "duplicate zk-ids are an error":
    let x = frFromBytesLE([byte 3]).get
    check coreZkIdRoot([x, x]).isErr

  test "input order does not matter — the builder sorts":
    let
      a = frFromBytesLE([byte 1]).get
      b = frFromBytesLE([byte 2]).get
      c = frFromBytesLE([byte 3]).get
    check coreZkIdRoot([a, b, c]).get == coreZkIdRoot([c, a, b]).get

  test "single leaf differs from the empty-subtree chain":
    let a = frFromBytesLE([byte 1]).get
    check coreZkIdRoot([a]).isOk

  test "reproduces the root the committed member-set proof was made against":
    # The core_set fixture proof was generated against the root of this
    # two-member set. The builder must reproduce it exactly.
    let metaText = readAllChars(fixtureDir / "core_set_meta.json").expect(
      "meta readable")
    let meta =
      try:
        parseJson(metaText)
      except CatchableError:
        checkpoint "meta must parse"
        fail()
        return
    var zkIds: seq[ZkPublicKey]
    for entry in meta["zk_ids"]:
      zkIds.add(frFromDecimal(entry.getStr).expect("zk id parses"))
    let
      publicText = readAllChars(fixtureDir / "public_core_set.json").expect(
        "public readable")
      signals = publicJsonToInputs(publicText).expect("public parses")
    check coreZkIdRoot(zkIds).get == signals[3]

suite "ledger/poq_verifier — end-to-end activity verification":
  # Reward parameters whose derived quotas equal the core_set fixture's
  # public inputs: core = ceil(8 * 1.0 * 4 / 2) = 16, leader = pow = 4.
  const fixtureParams = BlendRewardsParams(
    roundsPerEpoch: 8,
    messageFrequencyPerRound: 1.0,
    numBlendLayers: 4,
    dataReplicationFactor: 0,
    minimumNetworkSize: 2,
    activityThresholdSensitivity: 0)

  setup:
    check installFixtureVk()
    let
      fixture = loadFixture("core_set")
      metaText = readAllChars(fixtureDir / "core_set_meta.json").expect(
        "meta readable")
    let meta =
      try:
        parseJson(metaText)
      except CatchableError:
        checkpoint "meta must parse"
        fail()
        return
    var zkIds: seq[ZkPublicKey]
    for entry in meta["zk_ids"]:
      zkIds.add(frFromDecimal(entry.getStr).expect("zk id parses"))
    let
      rho = frFromDecimal(
        meta["selection_randomness"].getStr).expect("rho parses")
      memberIndex = uint64(meta["member_index"].getInt)
      # Provider 1 holds the proving member's zk-id (zk_ids[0]).
      snapshot = [
        (providerId: mkProvider(1), zkId: zkIds[0]),
        (providerId: mkProvider(2), zkId: zkIds[1])]
      activity = ActivityProof(
        epoch: 0,
        signingKey: fixture.signingKey,
        proofOfQuota: fixture.proofOfQuota,
        proofOfSelection: rho)

    proc rotatedWith(
        chain: PoqChainContext
    ): tuple[rewards: BlendRewards, randomness: FieldElement] =
      ## Rotate epoch 0 into the target with an epoch randomness ground
      ## until the fixture token passes the activity lottery.
      let token = BlendingToken(
        signingKey: fixture.signingKey,
        proofOfQuota: fixture.proofOfQuota,
        selectionRandomness: rho)
      for seed in 1'u64 .. 4096'u64:
        let
          randomness = frFromBytesLE(seed.toBytesLE()).expect("8 bytes")
          candidate = BlendRewards().rotateEpoch(
            0, 1, snapshot, randomness, fixtureParams, chain)
        doAssert candidate.rewards.target.isSome, "target must freeze"
        let state = candidate.rewards.target.get.state
        if hammingDistance(
            token, state.randomnessDigest, state.tokenParams.byteLen) <=
            state.tokenParams.threshold:
          return (candidate.rewards, randomness)
      doAssert false, "no epoch randomness passes the activity lottery"

  test "the frozen target reproduces the fixture's public inputs":
    let r = rotatedWith(fixture.public.chain).rewards
    let target = r.target.get.state
    check target.poqPublic.coreRoot == fixture.public.coreRoot
    check target.poqPublic.coreQuota == fixture.public.coreQuota
    check target.poqPublic.leaderQuota == fixture.public.leaderQuota
    check target.poqPublic.powQuota == fixture.public.powQuota
    check target.providers.get(mkProvider(1)).get.index == memberIndex

  test "a real activity proof is accepted by the real verifier":
    let r = rotatedWith(fixture.public.chain).rewards
    check recordActivity(
      r, activity, mkProvider(1), verifyProofOfQuota).isOk

  test "context from a different epoch rejects the proof (capture canary)":
    # A verifier wired to the wrong epoch's chain values must reject the
    # proof even though every other check passes.
    var wrongChain = fixture.public.chain
    wrongChain.polEpochNonce = frFromBytesLE([byte 0xDD]).get
    let r = rotatedWith(wrongChain).rewards
    check recordActivity(
      r, activity, mkProvider(1), verifyProofOfQuota
    ).error == InvalidProof

{.pop.}
