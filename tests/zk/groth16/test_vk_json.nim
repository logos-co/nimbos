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
  ../../../logos_chain/zk/groth16/vk_json

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  fixtureVk = testsDir / "../../fixtures/pol/verification_key.json"

# PoL circuit has 9 public inputs; snarkjs IC vector is `npub + 1` (extra slot
# is the constant-1 variable). Sanity threshold for "looks like a real VK".
const ExpectedIcLen = 10

suite "zk/groth16/vk_json":
  var fixtureText: string

  setup:
    fixtureText = readAllChars(fixtureVk).valueOr:
      check false
      return

  test "parseVk accepts canonical PoL VK fixture":
    let r = parseVk(fixtureText)
    check r.isOk
    let vk = r.get
    check vk.curve == "bn128"
    check vk.vpoints.pointsIC.len == ExpectedIcLen

  test "parseVk rejects malformed JSON":
    check parseVk("not json {").error == BadJson

  test "toVKey rejects wrong protocol":
    var j = parseVerificationKeyJson(fixtureText).valueOr:
      check false
      return
    j.protocol = "plonk"
    check toVKey(j).error == WrongProtocol

  test "toVKey rejects wrong curve":
    var j = parseVerificationKeyJson(fixtureText).valueOr:
      check false
      return
    j.curve = "bls12-381"
    check toVKey(j).error == WrongCurve

  test "toVKey rejects non-decimal field element":
    var j = parseVerificationKeyJson(fixtureText).valueOr:
      check false
      return
    j.alpha1[0] = "not-a-number"
    check toVKey(j).error == BadFieldElement

  test "toVKey rejects off-curve G1 point":
    # alpha1 = (0, 1) — passes Fp parsing but fails y² == x³ + 3 (y² = 1 ≠ 3).
    var j = parseVerificationKeyJson(fixtureText).valueOr:
      check false
      return
    j.alpha1 = ["0", "1", "1"]
    check toVKey(j).error == BadG1Point

{.pop.}
