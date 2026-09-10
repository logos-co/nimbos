# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/[os, strutils],
  unittest2,
  stew/io2,
  ../../logos_chain/core/mantle/[operations, proofs, tx_hashing, tx_types, poc_verifier],
  ../../logos_chain/ledger/
    [cryptarchia_state, leader_state, ledger, types],
  ../../logos_chain/utils/dynamic_merkle_tree as voucherTree,
  ../../logos_chain/zk/[groth16/utils, poc, poseidon2/hasher],
  ../core/mantle/test_helpers,
  ../ledger/sdp/test_helpers,
  ../zk/snarkjs_helpers,
  ./test_helpers

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  fixtureVk = testsDir / "../fixtures/poc/verification_key.json"
  fixtureProof = testsDir / "../fixtures/poc/proof.json"
  fixturePublic = testsDir / "../fixtures/poc/public.json"

proc fixtureLeaderInputs(): (ProofOfClaimProof, seq[FieldElement]) =
  poc.resetVkForTesting()
  let vkText = readAllChars(fixtureVk).valueOr:
    return (default(ProofOfClaimProof), @[])
  let vk = parseVk(vkText).valueOr:
    return (default(ProofOfClaimProof), @[])
  if poc.initVk(vk).isErr:
    return (default(ProofOfClaimProof), @[])
  let proofText = readAllChars(fixtureProof).valueOr:
    return (default(ProofOfClaimProof), @[])
  let publicText = readAllChars(fixturePublic).valueOr:
    return (default(ProofOfClaimProof), @[])
  let proof = proofJsonToBytes(proofText).valueOr:
    return (default(ProofOfClaimProof), @[])
  let publicInputs = publicJsonToInputs(publicText).valueOr:
    return (default(ProofOfClaimProof), @[])
  (proof, publicInputs)

func voucherBytes(seed: byte): RewardVoucher =
  var b: RewardVoucher
  b[0] = seed
  b

func mockVerifyProofOfClaim*(
    proof: ProofOfClaimProof, public: ProofOfClaimPublic
): Result[bool, PocLoadError] =
  ok(true)

func fieldFromSeed(seed: byte): FieldElement =
  var b: array[32, byte]
  b[0] = seed
  frFromBytesLEModOrder(b)

func makeLeaderState(
    claimableCount: uint64,
    leadersRewards: Value,
): LeaderState =
  var s = LeaderState.init()
  for i in 0 ..< claimableCount:
    s = s.recordBlockLeader(voucherBytes(byte(i + 1)))
  s.addPendingRewards(leadersRewards).addEpochVouchers().get

func mkFixtureLeaderState(): LeaderState =
  makeLeaderState(1'u64, 100'u64)

func mkFixtureLeaderClaimOp(
    publicInputs: openArray[FieldElement], rewardsRoot: RewardsRoot,
): LeaderClaimPayload =
  LeaderClaimPayload(
    rewardsRoot: rewardsRoot,
    voucherNullifier: publicInputs[0],
    publicKey: default(ZkPublicKey),
  )

func fixtureTxHash(publicInputs: openArray[FieldElement]): ZkHash =
  ## PoC fixture was generated with `mantle_tx_hash` as a circuit public input,
  ## not as `mantleTxHash(tx)` of a real mantle tx. Feed the canonical Fr bytes
  ## so `proofOfClaimPublic` matches the fixture.
  encodeFieldElement(publicInputs[1])

proc recordClaim(
    s: sink LeaderState, nf: VoucherNullifier
): tuple[state: LeaderState, reward: Value] =
  let op = LeaderClaimPayload(
    rewardsRoot: s.voucherTree.root(),
    voucherNullifier: nf,
    publicKey: default(ZkPublicKey),
  )
  let r = tryRecordClaim(s, op)
  if r.isErr:
    doAssert false, "tryRecordClaim failed: " & $r.error
  r.get

suite "ledger/leader_state":
  test "rewardShare splits leaders_rewards over unclaimed vouchers":
    let s = makeLeaderState(4'u64, 100'u64)
    check s.voucherTree.len() == 4
    check s.leadersRewards == 100
    check s.rewardShare() == 25
    let nf = default(VoucherNullifier)
    check nf notin s
    let claimed = s.recordClaim(nf)
    check claimed.state.rewardShare() == 25
    check claimed.state.leadersRewards == 75
    check nf in claimed.state

  test "rewardShare is zero when |voucher_cm| equals |voucher_nf|":
    var s = makeLeaderState(2'u64, 100'u64)
    s = s.recordClaim(fieldFromSeed(1)).state
    s = s.recordClaim(fieldFromSeed(2)).state
    check s.rewardShare() == 0

  test "rewardShare is stable across claims within an epoch":
    var s = makeLeaderState(4'u64, 100'u64)
    check s.rewardShare() == 25
    let nf = fieldFromSeed(1)
    let r = s.recordClaim(nf)
    s = r.state
    check r.reward == 25
    check s.leadersRewards == 75
    check nf in s
    check s.rewardShare() == 25

  test "non-divisible pool: early claims take floor, last gets residual":
    var s = makeLeaderState(3'u64, 100'u64)
    check s.rewardShare() == 33
    let r1 = s.recordClaim(fieldFromSeed(1))
    check r1.reward == 33
    s = r1.state
    check s.leadersRewards == 67
    check s.rewardShare() == 33
    let r2 = s.recordClaim(fieldFromSeed(2))
    check r2.reward == 33
    s = r2.state
    check s.leadersRewards == 34
    check s.rewardShare() == 34
    let r3 = s.recordClaim(fieldFromSeed(3))
    check r3.reward == 34
    s = r3.state
    check s.leadersRewards == 0
    check s.rewardShare() == 0

  test "addEpochVouchers updates tree, cm set size, and leaders rewards":
    let cm = voucherBytes(3'u8)
    let s = LeaderState.init().recordBlockLeader(cm)
      .addPendingRewards(40).addEpochVouchers().get
    check s.leadersRewards == 40
    check s.voucherTree.len() == 1

  test "addEpochVouchers accumulates across epoch boundaries":
    var s = LeaderState.init().recordBlockLeader(voucherBytes(1))
      .addPendingRewards(40)
    s = s.recordBlockLeader(voucherBytes(2)).recordBlockLeader(voucherBytes(3))
      .addPendingRewards(10).addEpochVouchers().get
    check s.leadersRewards == 50
    check s.voucherTree.len() == 3

suite "ledger/leader_claim — tryApplyLeaderClaim":
  var
    claimProof: ProofOfClaimProof
    publicInputs: seq[FieldElement]

  setup:
    (claimProof, publicInputs) = fixtureLeaderInputs()
    check publicInputs.len == 3

  test "happy path: fixture verify then claim debits pool and mints UTXO":
    let
      leader = mkFixtureLeaderState()
      txHash = fixtureTxHash(publicInputs)
      fixtureOp = mkFixtureLeaderClaimOp(publicInputs, publicInputs[2])
      ledgerOp = mkFixtureLeaderClaimOp(
        publicInputs, voucherTree.root(leader.voucherTree),
      )
    check verifyProofOfClaim(
      claimProof, proofOfClaimPublic(fixtureOp, publicInputs[2], txHash),
    ).get
    let cs = CryptarchiaState(utxos: UtxoStore.init(), leader: leader)
    let res = cs.tryApplyLeaderClaim(ledgerOp)
    check res.isOk
    
    let state = res.get
    check state.leader.leadersRewards == 0
    check ledgerOp.voucherNullifier in state.leader
    check state.utxos.len == 1

  test "allows zero-reward claim":
    let
      leader = makeLeaderState(1'u64, 0'u64)
      op = mkFixtureLeaderClaimOp(publicInputs, voucherTree.root(leader.voucherTree))
      r = CryptarchiaState(utxos: UtxoStore.init(), leader: leader)
        .tryApplyLeaderClaim(op)
    check r.isOk
    let state = r.get()
    check state.leader.leadersRewards == 0
    check op.voucherNullifier in state.leader
    check state.utxos.len == 1

  test "a 300 pool over 3 vouchers mints a 100-value note":
    let
      leader = makeLeaderState(3'u64, 300'u64)
      op = mkFixtureLeaderClaimOp(publicInputs, voucherTree.root(leader.voucherTree))
    check leader.rewardShare() == 100
    let r = CryptarchiaState(utxos: UtxoStore.init(), leader: leader)
      .tryApplyLeaderClaim(op)
    check r.isOk
    let
      state = r.get
      minted = Utxo(
        opId: opId(op),
        outputIndex: 0,
        note: Note(value: 100, zkPublicKey: op.publicKey),
      )
    check:
      state.leader.leadersRewards == 200
      state.leader.rewardShare() == 100 # unchanged for the remaining vouchers
      state.utxos.get(minted.id) == Opt.some(minted)

  test "rejects duplicate voucher nullifier":
    let
      leader = mkFixtureLeaderState()
      op = mkFixtureLeaderClaimOp(publicInputs, voucherTree.root(leader.voucherTree))
      recorded = leader.recordClaim(op.voucherNullifier)
      s0 = CryptarchiaState(utxos: UtxoStore.init(), leader: recorded.state)
      second = s0.tryApplyLeaderClaim(op)
    check second.isErr
    check second.error == DuplicatedVoucherNullifier

  test "rejects rewards root mismatch":
    let
      leader = mkFixtureLeaderState()
    var op = mkFixtureLeaderClaimOp(publicInputs, voucherTree.root(leader.voucherTree))
    op.rewardsRoot = fieldFromSeed(0xAB)
    let r = CryptarchiaState(utxos: UtxoStore.init(), leader: leader)
      .tryApplyLeaderClaim(op)
    check r.isErr
    check r.error == RewardsRootMismatch


suite "ledger/leader_claim — tryApplyHeader epoch hooks":
  test "epoch advance rolls in staged vouchers and rewards":
    let s0 = LedgerState.fromUtxos(@[], default(FieldElement), testSdpRegistry(), testLedgerConfig).get
    let s1 = s0.tryApplyHeader(slot = 1'u64, proof = mkProof(), cfg = testLedgerConfig).get
    var st = s1
    st.cryptarchiaLedger.leader = st.cryptarchiaLedger.leader
      .recordBlockLeader(voucherBytes(2'u8)).addPendingRewards(50'u64)
    let s2 = st.tryApplyHeader(slot = 100'u64, proof = mkProof(), cfg = testLedgerConfig).get
    let leader = s2.cryptarchiaLedger.leader
    check leader.leadersRewards == 50
    # Both the slot-1 header's voucher and the manually staged one roll in.
    check leader.voucherTree.len() == 2

{.pop.}
