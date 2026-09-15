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
  stew/[assign2, io2],
  ../../logos_chain/zk/poq,
  ../../logos_chain/zk/poseidon2/hasher,
  ./[helpers, snarkjs_helpers]

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  fixtureDir = testsDir.parentDir / "fixtures" / "poq"
  fixtureVk = fixtureDir / "verification_key.json"

type BranchFixture =
  tuple[proofBytes: array[ProofBytesLen, byte], input: PoqVerifierInput]

proc loadBranch(tag: string): BranchFixture =
  ## Split one wire fixture (`key_nullifier || compressed proof`) and its
  ## public signals.
  let
    bin = io2.readAllBytes(fixtureDir / ("proof_" & tag & ".bin")).expect(
      "fixture bin readable")
    publicText = readAllChars(fixtureDir / ("public_" & tag & ".json")).expect(
      "fixture public readable")
    signals = publicJsonToInputs(publicText).expect("fixture public parses")
  doAssert bin.len == 160, "wire proof-of-quota is 160 bytes"
  var proofBytes: array[ProofBytesLen, byte]
  assign(proofBytes, bin.toOpenArray(32, bin.high))
  let nullifier = frFromBytesLE(bin.toOpenArray(0, 31)).expect(
    "fixture nullifier canonical")
  doAssert nullifier == signals[0],
    "wire nullifier must equal the first public signal"
  (proofBytes, poqVerifierInput(signals).expect("12 signals"))

suite "zk/poq — loadVk":
  test "rejects missing file":
    let r = loadVk(uniqueTmpDir("missing-vk"))
    check r.error == VkFileMissing

  test "rejects garbage JSON":
    let dir = uniqueTmpDir("bad-vk")
    check createPath(dir / "poq").isOk
    check io2.writeFile(dir / "poq" / "verification_key.json", "not json {").isOk
    check loadVk(dir).error == VkInvalid

  test "rejects JSON with wrong protocol":
    let dir = uniqueTmpDir("wrong-proto-vk")
    check createPath(dir / "poq").isOk
    check io2.writeFile(
      dir / "poq" / "verification_key.json",
      """{"protocol":"plonk","curve":"bn128","vk_alpha_1":["0","0","1"],""" &
      """"vk_beta_2":[["0","0"],["0","0"],["1","0"]],""" &
      """"vk_gamma_2":[["0","0"],["0","0"],["1","0"]],""" &
      """"vk_delta_2":[["0","0"],["0","0"],["1","0"]],"IC":[]}""",
    ).isOk
    check loadVk(dir).error == VkInvalid

  test "accepts canonical fixture":
    # Build a synthetic bundle by copying the fixture VK into <tmp>/poq/.
    let
      dir = uniqueTmpDir("good-vk")
      vkBytes = readAllChars(fixtureVk).valueOr:
        check false
        return
    check createPath(dir / "poq").isOk
    check io2.writeFile(dir / "poq" / "verification_key.json", vkBytes).isOk
    let r = loadVk(dir)
    check r.isOk
    check r.get.curve == "bn128"

suite "zk/poq — verify":
  setup:
    poq.resetVkForTesting()
    let vkText = readAllChars(fixtureVk).valueOr:
      check false
      return
    let vk = parseVk(vkText).valueOr:
      check false
      return
    check poq.initVk(vk).isOk

  test "rejects when VK singleton not installed":
    poq.resetVkForTesting()
    let core = loadBranch("core")
    let r = verify(core.proofBytes, core.input)
    check r.error == VkNotLoaded

  test "double initVk returns VkAlreadyLoaded":
    let vkText = readAllChars(fixtureVk).valueOr:
      check false
      return
    let vk = parseVk(vkText).valueOr:
      check false
      return
    check poq.initVk(vk).error == VkAlreadyLoaded

  test "accepts every branch fixture — the verifier is branch-blind":
    # The three proofs use the three selector values. Nothing in the
    # public vector reveals which branch held.
    let core = loadBranch("core")
    check accepts(verify(core.proofBytes, core.input))
    for tag in ["leader", "pow"]:
      let branch = loadBranch(tag)
      check accepts(verify(branch.proofBytes, branch.input))

  test "rejects swapped coreRoot/polLedgerAged (signal-order canary)":
    # These two are the signals whose positions the `public [...]` clause
    # of the circuit would order differently.
    let core = loadBranch("core")
    var bad = core.input
    swap(bad.coreRoot, bad.polLedgerAged)
    check rejects(verify(core.proofBytes, bad))

  test "rejects swapped quota signals":
    let core = loadBranch("core")
    var bad = core.input
    swap(bad.coreQuota, bad.leaderQuota)
    check rejects(verify(core.proofBytes, bad))

  test "rejects any single mutated public input":
    let
      core = loadBranch("core")
      mutated = frFromBytesLE([byte 0xAB]).get
    for field in 0 ..< PoqPublicSignals:
      var
        bad = core.input
        signals = [
          addr bad.keyNullifier, addr bad.coreQuota, addr bad.leaderQuota,
          addr bad.coreRoot, addr bad.powQuota, addr bad.polLedgerAged,
          addr bad.kPartOne, addr bad.kPartTwo, addr bad.powBlendDifficulty,
          addr bad.polEpochNonce, addr bad.polT0, addr bad.polT1]
      signals[field][] = mutated
      check rejects(verify(core.proofBytes, bad))

  test "rejects mutated proof bytes":
    let core = loadBranch("core")
    var bad = core.proofBytes
    bad[0] = bad[0] xor 0x01
    check rejects(verify(bad, core.input))

{.pop.}
