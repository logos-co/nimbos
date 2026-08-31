# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/sequtils,
  unittest2,
  results,
  libp2p/crypto/ed25519/ed25519,
  ./test_helpers,
  ../../../logos_chain/ledger/sdp/blend_rewards

proc mkSnapshot(
    n: int
): seq[tuple[providerId: ProviderId, zkId: ZkPublicKey]] =
  ## n providers; provider i carries zk_id fe(i + 1), so the ascending
  ## zk sort gives provider i the index i.
  (0 ..< n).mapIt((
    providerId: mkProvider(byte(it + 1)),
    zkId: frFromBytesLE([byte(it + 1)]).get))

proc rotated(income: Value, n: int): BlendRewards =
  ## Fresh state with `income` accrued in epoch 0, rotated into a frozen
  ## epoch-0 target with an n-provider snapshot.
  var r = BlendRewards()
  r = r.addIncome(income).expect("income")
  r.rotateEpoch(0, 1, mkSnapshot(n), frFromBytesLE([byte 99]).get,
    testBlendLotteryParams).rewards

suite "ledger/sdp/blend_rewards":
  test "addIncome accumulates and rejects overflow":
    var r = BlendRewards()
    r = r.addIncome(30).expect("ok")
    r = r.addIncome(12).expect("ok")
    check r.epochIncome == 42
    check r.addIncome(high(Value)).error == BalanceOutOfRange

  test "no target epoch at genesis: submissions rejected":
    let r = BlendRewards()
    check recordActivity(
      r, mkActivity(frFromBytesLE([byte 1]).get, 0, 1),
      mkProvider(1), acceptAllPoq).error == TargetEpochNotSet

  test "rotation below minimum network size sets no target, drops income":
    let r = rotated(income = 500, n = 1)
    check r.target.isNone
    check r.epochIncome == 0

  test "a quota with no uint64 image sets no target, drops income":
    var absurdParams = testBlendLotteryParams
    absurdParams.messageFrequencyPerRound = 1e30
    var r = BlendRewards()
    r = r.addIncome(500).expect("income")
    let (next, minted) = r.rotateEpoch(
      0, 1, mkSnapshot(2), frFromBytesLE([byte 99]).get, absurdParams)
    check minted.len == 0
    check next.target.isNone
    check next.epochIncome == 0

  test "rotation freezes the target with the accrued income":
    let r = rotated(income = 500, n = 2)
    check r.target.isSome
    check r.target.get.state.epoch == 0
    check r.target.get.state.epochIncome == 500
    check r.epochIncome == 0

  test "single valid submission collects (income div 2) * 2":
    var r = rotated(income = 1001, n = 2)
    let rho = findRho(index = 0, membership = 2)
    r = recordActivity(
      r, mkActivity(rho, 0, 10), mkProvider(1), acceptAllPoq
    ).expect("valid submission")
    let (next, minted) = r.rotateEpoch(
      1, 2, mkSnapshot(2), frFromBytesLE([byte 98]).get, testBlendLotteryParams)
    check minted.len == 1
    # base = 1001 div (1 + 1) = 500; the sole submitter is premium.
    check minted[0].note.value == 1000
    check minted[0].note.zkPublicKey == frFromBytesLE([byte 1]).get
    check next.target.isSome

  test "no submissions: nothing minted, income forfeited":
    let (next, minted) = rotated(income = 700, n = 2).rotateEpoch(
      1, 2, mkSnapshot(2), frFromBytesLE([byte 98]).get, testBlendLotteryParams)
    check minted.len == 0
    check next.target.get.state.epochIncome == 0

  test "multi-epoch jump pays the frozen target but sets no new one":
    var r = rotated(income = 1001, n = 2)
    let rho = findRho(index = 0, membership = 2)
    r = recordActivity(
      r, mkActivity(rho, 0, 10), mkProvider(1), acceptAllPoq
    ).expect("valid submission")
    let (next, minted) = r.rotateEpoch(
      1, 3, mkSnapshot(2), frFromBytesLE([byte 98]).get, testBlendLotteryParams)
    check minted.len == 1
    check next.target.isNone

  test "duplicate submission is rejected":
    var r = rotated(income = 100, n = 2)
    let rho = findRho(index = 0, membership = 2)
    r = recordActivity(
      r, mkActivity(rho, 0, 10), mkProvider(1), acceptAllPoq
    ).expect("first submission")
    check recordActivity(
      r, mkActivity(rho, 0, 10), mkProvider(1), acceptAllPoq
    ).error == DuplicateActiveMessage

  test "wrong epoch and unknown provider are rejected":
    let
      r = rotated(income = 100, n = 2)
      rho = findRho(index = 0, membership = 2)
    check recordActivity(
      r, mkActivity(rho, 5, 10), mkProvider(1), acceptAllPoq
    ).error == InvalidEpoch
    check recordActivity(
      r, mkActivity(rho, 0, 10), mkProvider(9), acceptAllPoq
    ).error == UnknownProvider

  test "selection index and nullifier binding are verified":
    let
      r = rotated(income = 100, n = 2)
      wrongIndexRho = findRho(index = 1, membership = 2)
    # Provider 1 sits at index 0; a rho selecting index 1 must fail.
    check recordActivity(
      r, mkActivity(wrongIndexRho, 0, 10), mkProvider(1), acceptAllPoq
    ).error == InvalidTxProof
    var bad = mkActivity(findRho(0, 2), 0, 10)
    bad.proofOfQuota.keyNullifier = frFromBytesLE([byte 77]).get
    check recordActivity(
      r, bad, mkProvider(1), acceptAllPoq).error == InvalidTxProof

  test "an injected proof-of-quota rejection invalidates the submission":
    let rejectAll: PoqVerifier =
      proc(poq: ProofOfQuota, signingKey: Ed25519PublicKey): bool = false
    check recordActivity(
      rotated(income = 100, n = 2),
      mkActivity(findRho(0, 2), 0, 10), mkProvider(1), rejectAll
    ).error == InvalidTxProof

  test "three submitters, premium doubles, remainder dropped":
    var r = rotated(income = 1000, n = 3)
    let state = r.target.get.state
    # Derive the lottery outcome before submitting, so the expected split is
    # computed from the module's own distance function, not from the tracker.
    var
      proofs: array[3, ActivityProof]
      distances: array[3, uint64]
    for i in 0 ..< 3:
      proofs[i] = mkActivity(
        findRho(index = uint64(i), membership = 3), 0, byte(10 + i))
      distances[i] = hammingDistance(
        BlendingToken(
          signingKey: proofs[i].signingKey,
          proofOfQuota: proofs[i].proofOfQuota,
          selectionRandomness: proofs[i].proofOfSelection),
        state.randomnessDigest, state.tokenParams.byteLen)
    let
      minDistance = min(distances)
      premiums = distances.count(minDistance)
      base = 1000'u64 div uint64(3 + premiums)
    for i in 0 ..< 3:
      r = recordActivity(
        r, proofs[i], mkProvider(byte(i + 1)), acceptAllPoq
      ).expect("valid submission")
    let (_, minted) = r.rotateEpoch(
      1, 2, mkSnapshot(3), frFromBytesLE([byte 98]).get, testBlendLotteryParams)
    check minted.len == 3
    # Provider i carries zk_id fe(i + 1), so the ascending mint order is the
    # provider order and each note's exact value is pinned.
    for i in 0 ..< 3:
      check minted[i].note.value ==
        (if distances[i] == minDistance: base * 2 else: base)
    check minted.mapIt(it.outputIndex) == @[0'u64, 1, 2]
    check minted.mapIt(it.note.zkPublicKey) ==
      (1 .. 3).toSeq.mapIt(frFromBytesLE([byte it]).get)

{.pop.}
