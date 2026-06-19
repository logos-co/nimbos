# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/[os, sequtils, strutils, times],
  unittest2,
  stew/io2,
  poseidon2/types,
  ../../logos_chain/core/crypto/types as crypto_types,
  ../../logos_chain/zk/zksign,
  ./snarkjs_helpers

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  zksignFixtureDir = testsDir / "../fixtures/zksign"
  fixtureVk = zksignFixtureDir / "verification_key.json"
  fixtureProof = zksignFixtureDir / "proof.json"
  fixturePublic = zksignFixtureDir / "public.json"

proc uniqueTmpDir(tag: string): string =
  getTempDir() / ("nimbos_zksign_" & tag & "_" & $epochTime())

func seedFr(seed: byte): FieldElement =
  var b: array[32, byte]
  b[0] = seed
  frFromBytesLE(b).get

suite "zk/zksign — loadVk":
  test "rejects missing file":
    let r = loadVk(uniqueTmpDir("missing-vk"))
    check r.error == VkFileMissing

  test "rejects garbage JSON":
    let dir = uniqueTmpDir("bad-vk")
    check createPath(dir / "zksign").isOk
    check io2.writeFile(dir / "zksign" / "verification_key.json", "not json {").isOk
    check loadVk(dir).error == VkInvalid

  test "rejects JSON with wrong protocol":
    let dir = uniqueTmpDir("wrong-proto-vk")
    check createPath(dir / "zksign").isOk
    check io2.writeFile(
      dir / "zksign" / "verification_key.json",
      """{"protocol":"plonk","curve":"bn128","vk_alpha_1":["0","0","1"],""" &
      """"vk_beta_2":[["0","0"],["0","0"],["1","0"]],""" &
      """"vk_gamma_2":[["0","0"],["0","0"],["1","0"]],""" &
      """"vk_delta_2":[["0","0"],["0","0"],["1","0"]],"IC":[]}""",
    ).isOk
    check loadVk(dir).error == VkInvalid

  test "accepts a canonical Groth16 VK":
    let
      dir = uniqueTmpDir("good-vk")
      vkBytes = readAllChars(fixtureVk).valueOr:
        check false
        return
    check createPath(dir / "zksign").isOk
    check io2.writeFile(dir / "zksign" / "verification_key.json", vkBytes).isOk
    let r = loadVk(dir)
    check r.isOk
    check r.get.curve == "bn128"

suite "zk/zksign — singleton lifecycle":
  setup:
    zksign.resetVkForTesting()

  test "verify rejects when VK singleton not installed":
    let r = verify(default(array[ProofBytesLen, byte]), default(ZkSignVerifierInput))
    check r.error == VkNotLoaded

  test "double initVk returns VkAlreadyLoaded":
    let vkText = readAllChars(fixtureVk).valueOr:
      check false
      return
    let vk = parseVk(vkText).valueOr:
      check false
      return
    check zksign.initVk(vk).isOk
    check zksign.initVk(vk).error == VkAlreadyLoaded

  test "loadAndInitVk composes load + init":
    let
      dir = uniqueTmpDir("compose-vk")
      vkBytes = readAllChars(fixtureVk).valueOr:
        check false
        return
    check createPath(dir / "zksign").isOk
    check io2.writeFile(dir / "zksign" / "verification_key.json", vkBytes).isOk
    check zksign.loadAndInitVk(dir).isOk

  test "resetVkForTesting clears prior install":
    let vkText = readAllChars(fixtureVk).valueOr:
      check false
      return
    let vk = parseVk(vkText).valueOr:
      check false
      return
    check zksign.initVk(vk).isOk
    zksign.resetVkForTesting()
    check zksign.initVk(vk).isOk

suite "zk/zksign — zksignInput shape and padding":
  test "0 keys → all 32 slots padded, msg round-trips":
    let
      msg = seedFr(0xAB)
      r = zksignInput([], msg)
    check r.isOk

    let input = r.get
    check input.msg == msg
    for i in 0 ..< ZkSignMaxKeys:
      check input.publicKeys[i] == ZeroSecretKeyPublicKey

  test "1 key → slot 0 set, slots 1..31 padded":
    let
      k0 = seedFr(0x01)
      msg = seedFr(0xCD)
      r = zksignInput([k0], msg)
    check r.isOk

    let input = r.get
    check input.msg == msg
    check input.publicKeys[0] == k0
    for i in 1 ..< ZkSignMaxKeys:
      check input.publicKeys[i] == ZeroSecretKeyPublicKey

  test "32 keys → no padding, every slot is caller's":
    var keys: array[ZkSignMaxKeys, ZkPublicKey]
    for i in 0 ..< ZkSignMaxKeys:
      keys[i] = seedFr(byte(i + 1))
    let
      msg = seedFr(0xEF)
      r = zksignInput(keys, msg)
    check r.isOk

    let input = r.get
    check input.msg == msg
    for i in 0 ..< ZkSignMaxKeys:
      check input.publicKeys[i] == keys[i]

  test "33 keys → rejects with descriptive error":
    let
      keys = (0 ..< ZkSignMaxKeys + 1).mapIt(seedFr(byte(it + 1)))
      r = zksignInput(keys, seedFr(0xFF))
    check r.isErr
    check $r.error == "zksign: too many keys (max 32)"

proc loadFixtureProof(): array[ProofBytesLen, byte] =
  let proofText = readAllChars(fixtureProof).valueOr:
    raiseAssert "zksign fixture proof.json unreadable"
  proofJsonToBytes(proofText).valueOr:
    raiseAssert "zksign fixture proof.json malformed"

proc loadFixturePublic(): ZkSignVerifierInput =
  let
    publicText = readAllChars(fixturePublic).valueOr:
      raiseAssert "zksign fixture public.json unreadable"
    inputs = publicJsonToInputs(publicText).valueOr:
      raiseAssert "zksign fixture public.json malformed"
  doAssert inputs.len == ZkSignMaxKeys + 1,
    "zksign fixture public.json must have exactly 33 entries"
  result.msg = inputs[ZkSignMaxKeys]
  result.publicKeys[0 ..< ZkSignMaxKeys] = inputs.toOpenArray(0, ZkSignMaxKeys - 1)

suite "zk/zksign — verify against committed fixture":
  var
    proofBytes: array[ProofBytesLen, byte]
    input: ZkSignVerifierInput

  setup:
    zksign.resetVkForTesting()
    let
      vkText = readAllChars(fixtureVk).valueOr:
        check false
        return
      vk = parseVk(vkText).valueOr:
        check false
        return
    check zksign.initVk(vk).isOk
    proofBytes = loadFixtureProof()
    input = loadFixturePublic()

  test "accepts canonical 1-key vector":
    let r = verify(proofBytes, input)
    check r.isOk and r.get

  test "rejects bit-flipped proof byte":
    var bad = proofBytes
    bad[0] = bad[0] xor 0x01
    let r = verify(bad, input)
    check r.isOk and not r.get

  test "rejects mutated msg":
    var bad = input
    bad.msg = seedFr(0xCC)
    let r = verify(proofBytes, bad)
    check r.isOk and not r.get

  test "rejects swapped pk":
    var bad = input
    swap(bad.publicKeys[0], bad.publicKeys[1])
    let r = verify(proofBytes, bad)
    check r.isOk and not r.get

suite "zk/zksign — ZeroSecretKeyPublicKey constant cross-check":
  test "padding slots 1..31 of the 1-key fixture all equal ZeroSecretKeyPublicKey":
    # In the 1-key fixture, sks = [1, 0, 0, ..., 0]. The circuit derives each
    # PK as Poseidon2.compress(KDF, sk), so slots 1..31 of public.json carry
    # PK(SK=0). Our Nim constant is computed the same way; if it drifts from
    # what the Rust prover emits, this check fails.
    let input = loadFixturePublic()
    for i in 1 ..< ZkSignMaxKeys:
      check input.publicKeys[i] == ZeroSecretKeyPublicKey

{.pop.}
