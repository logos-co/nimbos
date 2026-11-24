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
  stew/endians2,
  stint,
  ../../logos_chain/core/types,
  ../../logos_chain/ledger/ledger,
  ../../logos_chain/utils/hash_trie_map,
  ../zk/zksign_helpers,
  ./sdp/test_helpers as sdp_test_helpers,
  ./test_helpers,
  ../core/mantle/test_helpers as mantle_test_helpers,
  ../testutil

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  zksignFixtureDir = testsDir / "../fixtures/zksign"
  zksignFixtureVk = zksignFixtureDir / "verification_key.json"
  fixtureProofPath = zksignFixtureDir / "proof.json"
  fixturePublicPath = zksignFixtureDir / "public.json"
  # testLedgerConfig.pow: 1_000_000 div 100.
  reward = 10_000'u64
  # The fee of a claim and its spend is 1_609 at the genesis prices of 1:
  # 590 + 590 execution gas and 429 bytes. A change of 8_000 leaves a
  # surplus of 2_000.
  change = 8_000'u64
  genesisNonce = default(FieldElement)

# The zksign fixture proof signs for this key.
let fixtureKey = mkRealZkPubKey(1)

proc mkState(cfg: LedgerConfig = testLedgerConfig): LedgerState =
  LedgerState.fromUtxos(
    @[], genesisNonce, testSdpRegistry(), cfg).expect("seed")

func anchorIds(
    publicKey: ZkPublicKey, nonce: FieldElement, target: UInt256,
    count: int, satisfying = true): seq[Hash32] =
  ## Setup only: the first `count` block ids, counted up from 1, whose
  ## ticket does (or does not) satisfy `target`.
  var
    ids = newSeqOfCap[Hash32](count)
    n = 1'u64
  while ids.len < count:
    var id: Hash32
    id[0 ..< 8] = n.toBytesLE
    id[31] = 0xaa # keeps the ids apart from `mkId`
    let ticket = puzzleTicket(ClaimPowRewardPayload(
      epochNonce: nonce, blockHash: id, publicKey: publicKey))
    if ticket.satisfies(target) == satisfying:
      ids.add(id)
    inc n
  ids

proc anchorId(
    nonce = genesisNonce, satisfying = true,
    publicKey = fixtureKey): Hash32 =
  anchorIds(
    publicKey, nonce, testLedgerConfig.pow.rewardTargetCap, 1, satisfying)[0]

func mkClaim(
    blockHash: Hash32, publicKey: ZkPublicKey): ClaimPowRewardPayload =
  ClaimPowRewardPayload(
    epochNonce: genesisNonce, blockHash: blockHash, publicKey: publicKey)

proc applyBlock(
    s: LedgerState, slot: SlotNumber, id: Hash32,
    txs: openArray[ValidSignedMantleTx] = [],
    cfg: LedgerConfig = testLedgerConfig): LedgerState =
  ## Setup only: one block through the header and the transaction steps.
  s.tryApplyHeader(slot, mkProof(), [], cfg).expect("header")
    .tryApplyTxns(txs, slot, id, cfg, acceptAllPoq).expect("block")

proc claimTx(claim: ClaimPowRewardPayload): ValidSignedMantleTx =
  ## A claim-only transaction under the fixture hash and proof.
  let stx = SignedMantleTx(
    tx: MantleTx(ops: @[createClaimPowRewardOp(claim)]),
    opProofs: @[OpProof(
      kind: opfClaimPowReward,
      claimPowRewardProof: loadProof(fixtureProofPath))])
  mkValidTx(mkHashedSignedTx(stx, loadTxHash(fixturePublicPath)))

func rewardNote(claim: ClaimPowRewardPayload): Utxo =
  # A restatement of the spec rule, not a copy of the ledger code: the
  # claim adds one note of the reward value for its key, with the id from
  # the claim op id and index 0.
  Utxo(
    opId: opId(claim), outputIndex: 0,
    note: Note(value: reward, zkPublicKey: claim.publicKey))

func spend(claim: ClaimPowRewardPayload): TransferPayload =
  TransferPayload(
    inputs: Inputs(noteIds: @[claim.rewardNote.id]),
    outputs: Outputs(notes: @[mkNote(change, pkSeed = 2)]))

proc claimAndSpendTx(claim: ClaimPowRewardPayload): ValidSignedMantleTx =
  ## A claim, then a transfer that spends the reward note. The fixture proof
  ## signs the fixture hash for the fixture key, so it serves both ops.
  let
    proof = loadProof(fixtureProofPath)
    stx = SignedMantleTx(
      tx: MantleTx(ops: @[
        createClaimPowRewardOp(claim), createTransferOp(claim.spend)]),
      opProofs: @[
        OpProof(kind: opfClaimPowReward, claimPowRewardProof: proof),
        OpProof(kind: opfTransfer, transferProof: proof)])
  mkValidTx(mkHashedSignedTx(stx, loadTxHash(fixturePublicPath)))

suite "ledger/pow claim":
  setup:
    check installZksignVk(zksignFixtureVk)

  test "tryApplyTx pays a valid claim":
    let
      anchor = anchorId()
      claim = mkClaim(anchor, fixtureKey)
    var s = mkState().applyBlock(1, anchor)
    let r = s.tryApplyTx(claimTx(claim), 0, 2, testLedgerConfig, acceptAllPoq)
    check:
      r.isOk
      s.latestUtxos.contains(claim.rewardNote.id)
      s.pow.rewardPool == 1_000_000'u64 - reward

  test "tryApplyTxns accepts a claim that pays its fee from the reward":
    let
      anchor = anchorId()
      claim = mkClaim(anchor, fixtureKey)
      s = mkState().applyBlock(1, anchor).applyBlock(
        2, mkId(0x02), [claimAndSpendTx(claim)])
      changeNote = Utxo(
        opId: opId(claim.spend).get, outputIndex: 0,
        note: mkNote(change, pkSeed = 2))
    check:
      not s.latestUtxos.contains(claim.rewardNote.id)
      s.latestUtxos.contains(changeNote.id)
      # The fee of 1_609 gives a share of 1_609 * 10 div 100. The claim adds
      # nothing to it.
      s.pow.pendingRefill == 160'u64

  test "tryApplyTx rejects a claim when the pool cannot pay":
    let anchors = anchorIds(
      fixtureKey, genesisNonce, testLedgerConfig.pow.rewardTargetCap, 3)
    # 50 * 1 div 100 = 0: no reward.
    var empty = testLedgerConfig
    empty.pow.genesisPool = 50
    var s1 = mkState(empty).applyBlock(1, anchors[0], cfg = empty)
    let r1 = s1.tryApplyTx(
      claimTx(mkClaim(anchors[0], fixtureKey)), 0, 2, empty, acceptAllPoq)
    check:
      s1.pow.epochReward == 0'u64
      r1.error == PowRewardUnavailable
    # A rate of 0 switches the claims off.
    var off = testLedgerConfig
    off.pow.rateNum = 0
    var s0 = mkState(off).applyBlock(1, anchors[0], cfg = off)
    let r0 = s0.tryApplyTx(
      claimTx(mkClaim(anchors[0], fixtureKey)), 0, 2, off, acceptAllPoq)
    check r0.error == PowRewardUnavailable
    # 1_000_000 * 50 div 100 = 500_000. The first claim leaves 500_000, which
    # covers one more reward exactly. The second claim empties the pool.
    var half = testLedgerConfig
    half.pow.rateNum = 50
    var s2 = mkState(half).applyBlock(1, anchors[0], cfg = half)
      .applyBlock(2, anchors[1], cfg = half)
      .applyBlock(3, anchors[2], cfg = half)
    let
      first = s2.tryApplyTx(
        claimTx(mkClaim(anchors[0], fixtureKey)), 0, 4, half, acceptAllPoq)
      second = s2.tryApplyTx(
        claimTx(mkClaim(anchors[1], fixtureKey)), 0, 4, half, acceptAllPoq)
      third = s2.tryApplyTx(
        claimTx(mkClaim(anchors[2], fixtureKey)), 0, 4, half, acceptAllPoq)
    check:
      first.isOk
      second.isOk
      s2.pow.rewardPool == 0'u64
      third.error == PowRewardUnavailable

  test "tryApplyTx rejects a claim on a block outside the window":
    let
      anchor = anchorId()
      tx = claimTx(mkClaim(anchor, fixtureKey))
      base = mkState().applyBlock(1, anchor)
    var
      unknown = mkState().applyBlock(1, mkId(0x01))
      late = base
      last = base
    let
      unknownResult = unknown.tryApplyTx(tx, 0, 2, testLedgerConfig, acceptAllPoq)
      # 52 - 1 = 51 is above the window of 50.
      lateResult = late.tryApplyTx(tx, 0, 52, testLedgerConfig, acceptAllPoq)
      lastResult = last.tryApplyTx(tx, 0, 51, testLedgerConfig, acceptAllPoq)
    check:
      unknownResult.error == PowBlockOutsideWindow
      lateResult.error == PowBlockOutsideWindow
      lastResult.isOk

  test "tryApplyTx accepts a claim on the genesis block":
    let genesisId = anchorId()
    var s = LedgerState.fromGenesis(
      testValidGenesisTx(), genesisId, genesisNonce, testSdpRegistry(),
      testLedgerConfig).expect("genesis state")
    let r = s.tryApplyTx(
      claimTx(mkClaim(genesisId, fixtureKey)), 0, 5, testLedgerConfig, acceptAllPoq)
    check r.isOk

  test "tryApplyTx accepts the previous epoch nonce and rejects an older one":
    # The block at slot 10 moves the running nonce away from the genesis
    # nonce before the snapshot at slot 60. So epoch 1 has a new nonce and
    # the genesis nonce is the previous nonce.
    let anchors = anchorIds(
      fixtureKey, genesisNonce, testLedgerConfig.pow.rewardTargetCap, 2)
    var s = mkState().applyBlock(10, mkId(0x10)).applyBlock(95, anchors[0])
      .tryApplyHeader(105, mkProof(), [], testLedgerConfig).expect("epoch 1")
    let previous = s.tryApplyTx(
      claimTx(mkClaim(anchors[0], fixtureKey)), 1, 105, testLedgerConfig, acceptAllPoq)
    check:
      s.epochs.activeEpoch.nonce != genesisNonce
      previous.isOk
    # In epoch 2 the genesis nonce is two epochs old.
    s = s.applyBlock(205, anchors[1])
    let older = s.tryApplyTx(
      claimTx(mkClaim(anchors[1], fixtureKey)), 2, 210, testLedgerConfig, acceptAllPoq)
    check older.error == PowEpochNonceMismatch

  test "tryApplyTx rejects a ticket that is not below the target":
    let anchor = anchorId(satisfying = false)
    var s = mkState().applyBlock(1, anchor)
    let r = s.tryApplyTx(
      claimTx(mkClaim(anchor, fixtureKey)), 0, 2, testLedgerConfig, acceptAllPoq)
    check r.error == PowTicketAboveTarget

  test "tryApplyTx rejects a ticket that was claimed":
    # The second try comes after an epoch boundary. A spent ticket stays
    # spent while its block is in the window.
    let
      anchor = anchorId()
      tx = claimTx(mkClaim(anchor, fixtureKey))
    var s = mkState().applyBlock(95, anchor)
    let first = s.tryApplyTx(tx, 0, 96, testLedgerConfig, acceptAllPoq)
    s = s.tryApplyHeader(100, mkProof(), [], testLedgerConfig).expect("epoch 1")
    let second = s.tryApplyTx(tx, 1, 101, testLedgerConfig, acceptAllPoq)
    check:
      first.isOk
      second.error == PowTicketClaimed

  test "tryApplyTx rejects a claim that another key signed":
    # The fixture proof signs for mkRealZkPubKey(1), not for this key.
    let
      otherKey = mkRealZkPubKey(2)
      anchor = anchorId(publicKey = otherKey)
    var s = mkState().applyBlock(1, anchor)
    let r = s.tryApplyTx(
      claimTx(mkClaim(anchor, otherKey)), 0, 2, testLedgerConfig,
      acceptAllPoq)
    check r.error == PermanentInvalidTxProof

  test "tryApplyTxns retargets after the block":
    # T = 1, F = 9, P = 10. Two claims give a demand of 1 * 2 + 9 * 1 = 11.
    var cfg = testLedgerConfig
    cfg.pow.targetClaimsPerBlock = stuint(1, 512)
    let
      cap = cfg.pow.rewardTargetCap
      anchors = anchorIds(fixtureKey, genesisNonce, cap, 2)
    var s = mkState(cfg).applyBlock(1, anchors[0], cfg = cfg)
      .applyBlock(2, anchors[1], cfg = cfg)
    check s.pow.difficultyReward == cap
    s = s.applyBlock(3, mkId(0x03), [
      claimAndSpendTx(mkClaim(anchors[0], fixtureKey)),
      claimAndSpendTx(mkClaim(anchors[1], fixtureKey))], cfg)
    let afterClaims = cap * 10.u256 div 11.u256
    check s.pow.difficultyReward == afterClaims
    # An empty block gives floor(afterClaims * 10 / 9). That is above the
    # cap, so the clamp returns the cap.
    s = s.applyBlock(4, mkId(0x04), cfg = cfg)
    check s.pow.difficultyReward == cap

  test "a block close drops tickets and blocks outside the window":
    let anchor = anchorId()
    var s = mkState().applyBlock(1, anchor)
    let r = s.tryApplyTx(
      claimTx(mkClaim(anchor, fixtureKey)), 0, 2, testLedgerConfig, acceptAllPoq)
    check:
      r.isOk
      s.pow.nullifiers.len == 1
    # 52 - 1 = 51 is above the window of 50.
    s = s.applyBlock(52, mkId(0x52))
    check:
      s.pow.nullifiers.len == 0
      anchor notin s.pow.blockSlots

{.pop.}
