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
  ../../../testsuite,
  results,
  libp2p/crypto/ed25519/ed25519,
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

proc mkTargetActivity(target: BlendTarget, nonce: Nonce = 1): ActiveMessage =
  ## Active message whose metadata proves selection at the provider's own
  ## index in the frozen target epoch.
  let
    state = target.registry.blendRewards.target.get.state
    index = state.providers.get(target.providerId).get.index
  ActiveMessage(
    declarationId: target.declId,
    nonce: nonce,
    metadata: mkActivity(findRho(index, 2), 0, 3))

suite "ledger/sdp/ops/active":
  test "tryApplySdpActive rejects unknown declaration":
    let seeded = seedDeclaration(pkSeed = 21, declareEpoch = 10)
    var unknown = ActiveMessage(
      declarationId: seeded.declId,
      nonce: 1,
    )
    unknown.declarationId[0] = byte(77)
    check execActive(seeded, unknown, 15).error == DeclarationNotFound

  test "tryApplySdpActive rejects a stale nonce":
    let
      seeded = seedDeclaration(pkSeed = 26, declareEpoch = 10)
      stale = ActiveMessage(
        declarationId: seeded.declId,
        nonce: 0,
      )
    check execActive(seeded, stale, 15).error == InvalidNonce

  test "rejects a report after withdraw_at":
    # Pins the SDP Active validity rule. The epoch boundary removes the
    # declaration first, so on a valid chain this path is defensive.
    var seeded = seedDeclaration(pkSeed = 24, declareEpoch = 1)
    installTestWithdraw(seeded.registry, WithdrawMessage(
      declarationId: seeded.declId,
      lockedNoteId: seeded.declaration.lockedNoteId,
      nonce: 1), withdrawAt = 5)
    let active = ActiveMessage(
      declarationId: seeded.declId, nonce: 2)
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
    check applied.blendRewards.target.get.tracker.submitted.len == 1
    let info = getDeclaration(applied.state, target.declId).get()
    check info.active == Opt.some(1'u32)
    check info.nonce == 1'u64

  test "a rejected proof of quota invalidates the op":
    check tryApplySdpActive(
      target.registry, mkTargetActivity(target), fixtureProof,
      fixtureTxHash, 1, rejectAllPoq).error == InvalidTxProof

{.pop.}
