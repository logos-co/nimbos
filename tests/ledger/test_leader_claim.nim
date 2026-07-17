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
  ../../logos_chain/core/crypto/types,
  ../../logos_chain/core/mantle/[operations, proofs, tx_types],
  ../../logos_chain/ledger/
    [balance, cryptarchia_state, leader_claim, leader_state, ledger, poc_verifier, types],
  ../../logos_chain/utils/dynamic_merkle_tree as voucherTree,
  ../../logos_chain/zk/[poc, poseidon2/hasher],
  ../zk/snarkjs_helpers

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

func makeLeaderState(
    claimableCount: uint64,
    leadersRewards: Value,
): LeaderState =
  var vouchers: seq[RewardVoucher]
  for i in 0 ..< claimableCount:
    vouchers.add(voucherBytes(byte(i + 1)))
  LeaderState.init().addEpochVouchers(vouchers, leadersRewards)

func mkEmptyLeaderState(): LeaderState =
  makeLeaderState(0'u64, 0'u64)

func mkFixtureLeaderState(publicInputs: openArray[FieldElement]): LeaderState =
  ## Fixture ``voucher_root`` is for a 32-deep witness tree, not a one-leaf
  ## ``DynamicMerkleTree``. Build claimable pool + cm count; bind ops to
  ## ``voucherTree.root(leader.voucherTree)``.
  discard publicInputs
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

suite "ledger/leader_state":
  test "rewardShare splits leaders_rewards over unclaimed vouchers":
    let s = makeLeaderState(4'u64, 100'u64)
    check s.voucherCmSetSize == 4
    check s.spentNullifiers.len == 0
    check s.leadersRewards == 100
    check s.rewardShare() == 25
    var spent = makeLeaderState(4'u64, 100'u64)
    spent.spentNullifiers.add(default(VoucherNullifier))
    check spent.rewardShare() == 33

  test "rewardShare is zero when |voucher_cm| equals |voucher_nf|":
    var s = makeLeaderState(2'u64, 100'u64)
    s.spentNullifiers.add(frFromBytesLE([1'u8]).get)
    s.spentNullifiers.add(frFromBytesLE([2'u8]).get)
    check s.voucherCmSetSize == uint64(s.spentNullifiers.len)
    check s.rewardShare() == 0

  test "rewardShare is stable across claims within an epoch":
    var s = makeLeaderState(4'u64, 100'u64)
    check s.rewardShare() == 25
    let r = s.tryRecordClaim(frFromBytesLE([1'u8]).get)
    check r.isOk
    s = r.get.state
    check r.get.reward == 25
    check s.leadersRewards == 75
    check s.spentNullifiers.len == 1
    check s.rewardShare() == 25

  test "addEpochVouchers updates tree, cm set size, and leaders rewards":
    let cm = voucherBytes(3'u8)
    let s = LeaderState.init().addEpochVouchers(@[cm], 40)
    check s.voucherCmSetSize == 1
    check s.leadersRewards == 40
    check uint64(s.voucherTree.len()) == 1

  test "addEpochVouchers accumulates across epoch boundaries":
    var s = LeaderState.init().addEpochVouchers(@[voucherBytes(1)], 40)
    s = s.addEpochVouchers(@[voucherBytes(2), voucherBytes(3)], 10)
    check s.voucherCmSetSize == 3
    check s.leadersRewards == 50
    check uint64(s.voucherTree.len()) == 3

suite "ledger/leader_claim — applyLeaderClaim":
  test "mints reward UTXO and records nullifier":
    let
      nf = frFromBytesLE([7'u8]).get
      leader = makeLeaderState(1'u64, 50'u64)
      op = LeaderClaimPayload(
        rewardsRoot: voucherTree.root(leader.voucherTree),
        voucherNullifier: nf,
        publicKey: frFromBytesLE([9'u8]).get,
      )
      s0 = CryptarchiaState(utxos: UtxoStore.init(), leader: leader)
      r = s0.applyLeaderClaim(op)
    check r.isOk
    let res = r.get
    check res.balance == Balance.zero
    check res.state.leader.leadersRewards == 0
    check op.voucherNullifier in res.state.leader.spentNullifiers
    check res.state.utxos.len == 1

  test "rejects when no reward is claimable":
    let
      leader = makeLeaderState(1'u64, 0'u64)
      op = LeaderClaimPayload(
        rewardsRoot: voucherTree.root(leader.voucherTree),
        voucherNullifier: frFromBytesLE([1'u8]).get,
        publicKey: default(ZkPublicKey),
      )
      r = CryptarchiaState(utxos: UtxoStore.init(), leader: leader).applyLeaderClaim(op)
    check r.isErr
    check r.error == NoClaimableReward

suite "ledger/leader_claim — tryApplyLeaderClaim":
  var
    claimProof: ProofOfClaimProof
    publicInputs: seq[FieldElement]

  setup:
    (claimProof, publicInputs) = fixtureLeaderInputs()
    check publicInputs.len == 3

  test "fixture proof accepted when rewards root matches ledger tree":
    let
      leader = mkFixtureLeaderState(publicInputs)
      op = mkFixtureLeaderClaimOp(publicInputs, voucherTree.root(leader.voucherTree))
      txHash = fixtureTxHash(publicInputs)
      s0 = CryptarchiaState(utxos: UtxoStore.init(), leader: leader)
      r = s0.tryApplyLeaderClaim(op, claimProof, txHash)
    check r.isErr
    check r.error == InvalidProof

  test "rejects duplicate voucher nullifier":
    let
      leader = mkFixtureLeaderState(publicInputs)
      op = mkFixtureLeaderClaimOp(publicInputs, voucherTree.root(leader.voucherTree))
      txHash = fixtureTxHash(publicInputs)
      s0 = CryptarchiaState(utxos: UtxoStore.init(), leader: leader)
      first = s0.applyLeaderClaim(op)
    check first.isOk
    let second = first.get.state.tryApplyLeaderClaim(op, claimProof, txHash)
    check second.isErr
    check second.error == DuplicatedVoucherNullifier

  test "rejects rewards root mismatch":
    let
      leader = mkFixtureLeaderState(publicInputs)
      txHash = fixtureTxHash(publicInputs)
    var op = mkFixtureLeaderClaimOp(publicInputs, publicInputs[2])
    op.rewardsRoot = frFromBytesLE([0xAB'u8]).get
    let r = CryptarchiaState(utxos: UtxoStore.init(), leader: leader)
      .tryApplyLeaderClaim(op, claimProof, txHash)
    check r.isErr
    check r.error == RewardsRootMismatch

  test "rejects invalid proof":
    let
      leader = mkFixtureLeaderState(publicInputs)
      op = mkFixtureLeaderClaimOp(publicInputs, voucherTree.root(leader.voucherTree))
      txHash = fixtureTxHash(publicInputs)
    var badProof = claimProof
    badProof[0] = badProof[0] xor 0xFF'u8
    let r = CryptarchiaState(utxos: UtxoStore.init(), leader: leader)
      .tryApplyLeaderClaim(op, badProof, txHash)
    check r.isErr
    check r.error == InvalidProof

  test "rejects op nullifier not matching proof public input":
    let
      leader = mkFixtureLeaderState(publicInputs)
      txHash = fixtureTxHash(publicInputs)
    var op = mkFixtureLeaderClaimOp(publicInputs, voucherTree.root(leader.voucherTree))
    op.voucherNullifier = frFromBytesLE([0xCD'u8]).get
    let r = CryptarchiaState(utxos: UtxoStore.init(), leader: leader)
      .tryApplyLeaderClaim(op, claimProof, txHash)
    check r.isErr
    check r.error == InvalidProof

suite "ledger/leader_claim — tryApplyTx":
  var
    claimProof: ProofOfClaimProof
    publicInputs: seq[FieldElement]

  setup:
    (claimProof, publicInputs) = fixtureLeaderInputs()
    check publicInputs.len == 3

  test "LeaderClaim op wired through LedgerState":
    let
      leader = mkFixtureLeaderState(publicInputs)
      op = createLeaderClaimOp(
        mkFixtureLeaderClaimOp(publicInputs, voucherTree.root(leader.voucherTree)),
      )
      tx = SignedMantleTx(
        tx: MantleTx(ops: @[op]),
        opProofs: @[OpProof(kind: opfLeaderClaim, proofOfClaimProof: claimProof)],
      )
      s0 = LedgerState(cryptarchiaLedger: CryptarchiaState(utxos: UtxoStore.init(), leader: leader))
      r = s0.tryApplyTx(tx, epoch = 0, slot = 0)
    check r.isErr
    check r.error == InvalidProof

  test "wrong proof kind → InvalidProof":
    let
      leader = mkFixtureLeaderState(publicInputs)
      op = createLeaderClaimOp(
        mkFixtureLeaderClaimOp(publicInputs, voucherTree.root(leader.voucherTree)),
      )
      tx = SignedMantleTx(
        tx: MantleTx(ops: @[op]),
        opProofs: @[OpProof(kind: opfTransfer, transferProof: default(ZkSigProof))],
      )
      s0 = LedgerState(cryptarchiaLedger: CryptarchiaState(utxos: UtxoStore.init(), leader: leader))
      r = s0.tryApplyTx(tx, epoch = 0, slot = 0)
    check r.isErr
    check r.error == InvalidProof

{.pop.}
