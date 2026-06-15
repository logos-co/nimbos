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
  ../../logos_chain/zk/pol,
  ./snarkjs_helpers

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  fixtureVk = testsDir / "../fixtures/pol/verification_key.json"
  fixtureProof = testsDir / "../fixtures/pol/proof.json"
  fixturePublic = testsDir / "../fixtures/pol/public.json"

func toPolInput(s: openArray[FieldElement]): PolVerifierInput =
  # Positional mapping from the public.json ordering to the typed input.
  # Order is the canonical 9-field spec from `pol/inputs.rs:127-138`.
  doAssert s.len == 9, "public.json must have exactly 9 entries for PoL"
  PolVerifierInput(
    entropyContribution: s[0],
    slotNumber: s[1],
    epochNonce: s[2],
    lottery0: s[3],
    lottery1: s[4],
    agedRoot: s[5],
    latestRoot: s[6],
    leaderPk1: s[7],
    leaderPk2: s[8],
  )

proc uniqueTmpDir(tag: string): string =
  # Per-test unique subdir under the system temp dir; OS cleans up eventually.
  # No teardown — keeps test bodies focused on the assertion.
  getTempDir() / ("nimbos_pol_" & tag & "_" & $epochTime())

suite "zk/pol — loadVk":
  test "rejects missing file":
    let r = loadVk(uniqueTmpDir("missing-vk"))
    check r.error == VkFileMissing

  test "rejects garbage JSON":
    let dir = uniqueTmpDir("bad-vk")
    check createPath(dir / "pol").isOk
    check io2.writeFile(dir / "pol" / "verification_key.json", "not json {").isOk
    check loadVk(dir).error == VkInvalid

  test "rejects JSON with wrong protocol":
    let dir = uniqueTmpDir("wrong-proto-vk")
    check createPath(dir / "pol").isOk
    check io2.writeFile(
      dir / "pol" / "verification_key.json",
      """{"protocol":"plonk","curve":"bn128","vk_alpha_1":["0","0","1"],""" &
      """"vk_beta_2":[["0","0"],["0","0"],["1","0"]],""" &
      """"vk_gamma_2":[["0","0"],["0","0"],["1","0"]],""" &
      """"vk_delta_2":[["0","0"],["0","0"],["1","0"]],"IC":[]}""",
    ).isOk
    check loadVk(dir).error == VkInvalid

  test "accepts canonical fixture":
    # Build a synthetic bundle by copying the fixture VK into <tmp>/pol/.
    let
      dir = uniqueTmpDir("good-vk")
      vkBytes = readAllChars(fixtureVk).valueOr:
        check false
        return
    check createPath(dir / "pol").isOk
    check io2.writeFile(dir / "pol" / "verification_key.json", vkBytes).isOk
    let r = loadVk(dir)
    check r.isOk
    check r.get.curve == "bn128"

suite "zk/pol — verify":
  var
    proofBytes: array[ProofBytesLen, byte]
    input: PolVerifierInput

  setup:
    pol.resetVkForTesting()
    let vkText = readAllChars(fixtureVk).valueOr:
      check false
      return
    let proofText = readAllChars(fixtureProof).valueOr:
      check false
      return
    let publicText = readAllChars(fixturePublic).valueOr:
      check false
      return
    let vk = parseVk(vkText).valueOr:
      check false
      return
    check pol.initVk(vk).isOk
    proofBytes = proofJsonToBytes(proofText).valueOr:
      check false
      return
    let inputsSeq = publicJsonToInputs(publicText).valueOr:
      check false
      return
    input = toPolInput(inputsSeq)

  test "rejects when VK singleton not installed":
    pol.resetVkForTesting()
    let r = verify(proofBytes, input)
    check r.error == VkNotLoaded

  test "double initVk returns VkAlreadyLoaded":
    let vkText = readAllChars(fixtureVk).valueOr:
      check false
      return
    let vk = parseVk(vkText).valueOr:
      check false
      return
    check pol.initVk(vk).error == VkAlreadyLoaded

  test "accepts canonical PoL test vector":
    let r = verify(proofBytes, input)
    check r.isOk and r.get

  test "rejects swapped slot/epochNonce":
    var bad = input
    swap(bad.slotNumber, bad.epochNonce)
    let r = verify(proofBytes, bad)
    check r.isOk and not r.get

  test "rejects mutated entropyContribution":
    var bad = input
    bad.entropyContribution = input.slotNumber
    let r = verify(proofBytes, bad)
    check r.isOk and not r.get

{.pop.}
