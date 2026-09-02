# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/[os, strutils, times],
  unittest2,
  stew/io2,
  ../../logos_chain/zk/poq,
  ../../logos_chain/zk/poseidon2/hasher,
  ./snarkjs_helpers

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  fixtureDir = testsDir / "../fixtures/poq"
  fixtureVk = fixtureDir / "verification_key.json"

func toPoqInput(s: openArray[FieldElement]): PoqVerifierInput =
  # Positional mapping from the public.json ordering to the typed input.
  # Order is the 12-signal vector the proof-of-quota spec pins.
  doAssert s.len == 12, "public.json must have exactly 12 entries for PoQ"
  PoqVerifierInput(
    keyNullifier: s[0],
    coreQuota: s[1],
    leaderQuota: s[2],
    coreRoot: s[3],
    powQuota: s[4],
    polLedgerAged: s[5],
    kPartOne: s[6],
    kPartTwo: s[7],
    powBlendDifficulty: s[8],
    polEpochNonce: s[9],
    polT0: s[10],
    polT1: s[11])

proc loadBranch(
    tag: string
): tuple[proofBytes: array[ProofBytesLen, byte], input: PoqVerifierInput] =
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
  proofBytes[0 ..< ProofBytesLen] = bin.toOpenArray(32, bin.high)
  let nullifier = frFromBytesLE(bin.toOpenArray(0, 31)).expect(
    "fixture nullifier canonical")
  doAssert nullifier == signals[0],
    "wire nullifier must equal the first public signal"
  (proofBytes, toPoqInput(signals))

# Several tests share the core fixture. Load it once on first use.
var coreCache: Opt[
  tuple[proofBytes: array[ProofBytesLen, byte], input: PoqVerifierInput]]

proc coreFixture(): tuple[
    proofBytes: array[ProofBytesLen, byte], input: PoqVerifierInput] =
  if coreCache.isNone:
    coreCache = Opt.some(loadBranch("core"))
  coreCache.get

proc uniqueTmpDir(tag: string): string =
  # Per-test unique subdir under the system temp dir. The OS cleans it
  # up eventually. No teardown keeps test bodies focused on the assertion.
  getTempDir() / ("nimbos_poq_" & tag & "_" & $epochTime())

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
    let core = coreFixture()
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
    let core = coreFixture()
    check verify(core.proofBytes, core.input).get
    for tag in ["leader", "pow"]:
      let branch = loadBranch(tag)
      let r = verify(branch.proofBytes, branch.input)
      check r.isOk and r.get

  test "rejects swapped coreRoot/polLedgerAged (signal-order canary)":
    # These two are the signals whose positions the `public [...]` clause
    # of the circuit would order differently.
    let core = coreFixture()
    var bad = core.input
    swap(bad.coreRoot, bad.polLedgerAged)
    let r = verify(core.proofBytes, bad)
    check r.isOk and not r.get

  test "rejects swapped quota signals":
    let core = coreFixture()
    var bad = core.input
    swap(bad.coreQuota, bad.leaderQuota)
    let r = verify(core.proofBytes, bad)
    check r.isOk and not r.get

  test "rejects any single mutated public input":
    let
      core = coreFixture()
      mutated = frFromBytesLE([byte 0xAB]).get
    for field in 0 ..< 12:
      var
        bad = core.input
        signals = [
          addr bad.keyNullifier, addr bad.coreQuota, addr bad.leaderQuota,
          addr bad.coreRoot, addr bad.powQuota, addr bad.polLedgerAged,
          addr bad.kPartOne, addr bad.kPartTwo, addr bad.powBlendDifficulty,
          addr bad.polEpochNonce, addr bad.polT0, addr bad.polT1]
      signals[field][] = mutated
      let r = verify(core.proofBytes, bad)
      check r.isOk and not r.get

  test "rejects mutated proof bytes":
    let core = coreFixture()
    var bad = core.proofBytes
    bad[0] = bad[0] xor 0x01
    let r = verify(bad, core.input)
    check r.isOk and not r.get

{.pop.}
