# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[os, strutils],
  unittest2,
  ../test_helpers,
  ../../../zk/zksign_helpers

from ../../../core/mantle/test_helpers import mkRealZkPubKey

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  zksignFixtureDir = testsDir / "../../../fixtures/zksign"
  zksignFixtureVk = zksignFixtureDir / "verification_key.json"
  zksignFixtureProof = zksignFixtureDir / "proof.json"
  zksignFixturePublic = zksignFixtureDir / "public.json"

type BlendTarget = object
  registry: SdpRegistry
  declId: DeclarationId
  providerId: ProviderId

proc seedBlendTarget(): BlendTarget =
  ## Registry holding one blend declaration, with epoch 0 frozen as the
  ## reward target over that provider and one other.
  # The declaration's zk_id is the fixture prover's public key, so the
  # committed ZkSig proof verifies against the fixture tx hash.
  let
    providerId = mkProvider(7)
    declaration = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[mkLocator(30304)],
      providerId: providerId,
      lockedNoteId: default(NoteId),
      zkId: mkRealZkPubKey(1))
  var registry = testSdpRegistry()
  let declId = installTestDeclaration(registry, declaration, 1)
  registry.blendRewards = registry.blendRewards.rotateEpoch(
    0, 1,
    [(providerId: providerId, zkId: declaration.zkId),
     (providerId: mkProvider(8), zkId: frFromBytesLE([byte 9]).get)],
    frFromBytesLE([byte 5]).get, testBlendLotteryParams, testPoqChain).rewards
  BlendTarget(registry: registry, declId: declId, providerId: providerId)

proc mkTargetActivity(target: BlendTarget): ActiveMessage =
  ## Active message whose metadata proves selection at the provider's own
  ## index in the frozen target epoch.
  let
    state = target.registry.blendRewards.target.get.state
    index = state.providers.get(target.providerId).get.index
    created = getDeclaration(target.registry.state, target.declId).get.created
  ActiveMessage(
    declarationId: target.declId,
    nonce: nonce(created, 1),
    metadata: mkActivity(findRho(index, 2), 0, 3))

suite "ledger/sdp/ops/active":
  test "tryApplySdpActive rejects unknown declaration":
    let seeded = seedDeclaration(pkSeed = 21, declareEpoch = 10)
    var unknown = ActiveMessage(
      declarationId: seeded.declId,
      nonce: nonce(10, 1),
    )
    unknown.declarationId[0] = byte(77)
    check execActive(seeded, unknown, 15).error == DeclarationNotFound

  test "tryApplySdpActive rejects a nonce outside the lifecycle or sequence":
    # A packed u64 nonce comparison accepts nonce(11, 6) and fails this.
    var seeded = seedDeclaration(pkSeed = 26, declareEpoch = 10)
    let declaration = getDeclaration(seeded.registry.state, seeded.declId).get()
    seeded.registry = applySdpActive(
      seeded.registry,
      ActiveMessage(declarationId: seeded.declId, nonce: nonce(10, 5)),
      declaration, 11)
    for stale in [
        nonce(11, 6), nonce(9, high(uint32)), nonce(10, 5), nonce(10, 4)]:
      checkpoint("nonce " & $stale)
      let active = ActiveMessage(declarationId: seeded.declId, nonce: stale)
      check execActive(seeded, active, 15).error == InvalidNonce

  test "rejects a report after withdraw_at":
    # Pins the SDP Active validity rule. The epoch boundary removes the
    # declaration first, so on a valid chain this path is defensive.
    var seeded = seedDeclaration(pkSeed = 24, declareEpoch = 1)
    installTestWithdraw(seeded.registry, WithdrawMessage(
      declarationId: seeded.declId, nonce: nonce(1, 1)), withdrawAt = 5)
    let active = ActiveMessage(
      declarationId: seeded.declId, nonce: nonce(1, 2))
    check execActive(seeded, active, 6).error == AlreadyWithdrawn

suite "ledger/sdp/ops/active — blend activity":
  setup:
    check installZksignVk(zksignFixtureVk)
    let
      fixtureProof = loadProof(zksignFixtureProof)
      fixtureTxHash = loadTxHash(zksignFixturePublic)
      target = seedBlendTarget()

  test "a valid activity proof is recorded against the target epoch":
    let applied = tryApplySdpActive(
      target.registry, mkTargetActivity(target), fixtureProof,
      fixtureTxHash, 1, acceptAllPoq).expect("valid blend activity")
    let info = getDeclaration(applied.state, target.declId).get()
    check:
      applied.blendRewards.target.get.tracker.submitted.len == 1
      info.active == Opt.some(1'u32)
      info.nonce == nonce(1, 1)

  test "a rejected proof of quota invalidates the op":
    check tryApplySdpActive(
      target.registry, mkTargetActivity(target), fixtureProof,
      fixtureTxHash, 1, rejectAllPoq).error == InvalidTxProof

{.pop.}
