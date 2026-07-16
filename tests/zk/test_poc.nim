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
  ../../logos_chain/zk/poc,
  ./snarkjs_helpers

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  fixtureVk = testsDir / "../fixtures/poc/verification_key.json"
  fixtureProof = testsDir / "../fixtures/poc/proof.json"
  fixturePublic = testsDir / "../fixtures/poc/public.json"

func toPocInput(s: openArray[FieldElement]): PocVerifierInput =
  doAssert s.len == 3, "public.json must have exactly 3 entries for PoC"
  PocVerifierInput(
    voucherNullifier: s[0],
    mantleTxHashFr: s[1],
    voucherRoot: s[2],
  )

proc uniqueTmpDir(tag: string): string =
  getTempDir() / ("nimbos_poc_" & tag & "_" & $epochTime())

suite "zk/poc — loadVk":
  test "rejects missing file":
    let r = loadVk(uniqueTmpDir("missing-vk"))
    check r.error == VkFileMissing

  test "rejects garbage JSON":
    let dir = uniqueTmpDir("bad-vk")
    check createPath(dir / "poc").isOk
    check io2.writeFile(dir / "poc" / "verification_key.json", "not json {").isOk
    check loadVk(dir).error == VkInvalid

  test "accepts canonical fixture":
    let
      dir = uniqueTmpDir("good-vk")
      vkBytes = readAllChars(fixtureVk).valueOr:
        check false
        return
    check createPath(dir / "poc").isOk
    check io2.writeFile(dir / "poc" / "verification_key.json", vkBytes).isOk
    let r = loadVk(dir)
    check r.isOk
    check r.get.curve == "bn128"

suite "zk/poc — verify":
  var
    proofBytes: array[ProofBytesLen, byte]
    input: PocVerifierInput

  setup:
    poc.resetVkForTesting()
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
    check poc.initVk(vk).isOk
    proofBytes = proofJsonToBytes(proofText).valueOr:
      check false
      return
    let inputsSeq = publicJsonToInputs(publicText).valueOr:
      check false
      return
    input = toPocInput(inputsSeq)

  test "rejects when VK singleton not installed":
    poc.resetVkForTesting()
    let r = verify(proofBytes, input)
    check r.error == VkNotLoaded

  test "double initVk returns VkAlreadyLoaded":
    let vkText = readAllChars(fixtureVk).valueOr:
      check false
      return
    let vk = parseVk(vkText).valueOr:
      check false
      return
    check poc.initVk(vk).error == VkAlreadyLoaded

  test "accepts canonical PoC test vector":
    let r = verify(proofBytes, input)
    check r.isOk and r.get

  test "rejects swapped voucher root and nullifier":
    var bad = input
    swap(bad.voucherRoot, bad.voucherNullifier)
    let r = verify(proofBytes, bad)
    check r.isOk and not r.get

  test "rejects mutated mantle tx hash":
    var bad = input
    bad.mantleTxHashFr = input.voucherRoot
    let r = verify(proofBytes, bad)
    check r.isOk and not r.get

{.pop.}
