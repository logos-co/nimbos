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
  libp2p/crypto/ed25519/ed25519,
  ../../logos_chain/core/types,
  ../../logos_chain/core/crypto/types,
  ../../logos_chain/core/mantle/primitives,
  ../../logos_chain/ledger/pol_verifier,
  ../../logos_chain/zk/pol,
  ../zk/snarkjs_helpers

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  fixtureVk = testsDir / "../fixtures/pol/verification_key.json"
  fixtureProof = testsDir / "../fixtures/pol/proof.json"
  fixturePublic = testsDir / "../fixtures/pol/public.json"
  fixtureSlot = SlotNumber(511)  # hardcoded from public.json (inputs[1])

# Reconstruct the wire-format `ProofOfLeadership` from the canonical Groth16
# inputs. Inverts what verifyLeaderProof does internally: entropyContribution
# Fr → 32 LE bytes; (leaderPk1, leaderPk2) Fr halves → 16 bytes each → 32-byte
# Ed25519 raw key. libp2p `EdPublicKey.init` is length-only (no curve
# validation), so synthetic key bytes are accepted.
proc reconstructPol(
    proofBytes: array[ProofBytesLen, byte],
    inputs: seq[FieldElement],
): ProofOfLeadership =
  doAssert inputs.len == 9
  let
    pk1Bytes = inputs[7].toBytes()
    pk2Bytes = inputs[8].toBytes()
  var pkRaw: array[32, byte]
  for i in 0 ..< 16: pkRaw[i] = pk1Bytes[i]
  for i in 0 ..< 16: pkRaw[16 + i] = pk2Bytes[i]
  var leaderKey: Ed25519PublicKey
  doAssert leaderKey.init(pkRaw)
  ProofOfLeadership(
    proof: proofBytes,
    entropyContribution: inputs[0].toBytes(),
    leaderKey: leaderKey,
    leaderVoucher: default(RewardVoucher),
  )

proc reconstructLeaderPublic(inputs: seq[FieldElement]): LeaderPublic =
  doAssert inputs.len == 9
  LeaderPublic(
    slot: fixtureSlot,
    epochNonce: inputs[2],
    lottery0: inputs[3],
    lottery1: inputs[4],
    agedRoot: inputs[5],
    latestRoot: inputs[6],
  )

suite "ledger/pol_verifier":
  var
    polProof: ProofOfLeadership
    public: LeaderPublic

  setup:
    pol.resetVkForTesting()
    let vkText = readAllChars(fixtureVk).valueOr:
      check false
      return
    let vk = parseVk(vkText).valueOr:
      check false
      return
    check pol.initVk(vk).isOk
    let proofText = readAllChars(fixtureProof).valueOr:
      check false
      return
    let publicText = readAllChars(fixturePublic).valueOr:
      check false
      return
    let proofBytes = proofJsonToBytes(proofText).valueOr:
      check false
      return
    let inputsSeq = publicJsonToInputs(publicText).valueOr:
      check false
      return
    polProof = reconstructPol(proofBytes, inputsSeq)
    public = reconstructLeaderPublic(inputsSeq)

  test "genesis sentinel accepted (no Groth16 invocation)":
    # All-zero / default ProofOfLeadership matches the genesis sentinel and
    # short-circuits before reaching pol.verify — VK validity irrelevant.
    let genesis = default(ProofOfLeadership)
    let anyPublic = default(LeaderPublic)
    let r = verifyLeaderProof(genesis, anyPublic)
    check r.isOk and r.get

  test "real fixture accepted end-to-end":
    let r = verifyLeaderProof(polProof, public)
    check r.isOk and r.get

  test "rejects wrong slot":
    var badPublic = public
    badPublic.slot = SlotNumber(fixtureSlot.uint64 + 1)
    let r = verifyLeaderProof(polProof, badPublic)
    check r.isOk and not r.get

  test "rejects wrong epochNonce":
    var badPublic = public
    badPublic.epochNonce = public.lottery0  # any different valid Fr
    let r = verifyLeaderProof(polProof, badPublic)
    check r.isOk and not r.get

  test "rejects mutated leaderKey":
    var badPol = polProof
    var raw: array[32, byte]
    raw[0] = 0x42  # arbitrary non-zero, non-fixture key bytes
    discard badPol.leaderKey.init(raw)
    let r = verifyLeaderProof(badPol, public)
    check r.isOk and not r.get

  test "rejects entropyContribution >= BN254 modulus":
    # All-0xFF entropy is guaranteed to exceed the BN254 scalar modulus. The
    # isNone guard inside verifyLeaderProof must reject cleanly without raising.
    var badPol = polProof
    for i in 0 ..< 32:
      badPol.entropyContribution[i] = 0xFF'u8
    let r = verifyLeaderProof(badPol, public)
    check r.isOk and not r.get

  # Byte-level proof mutation covered at the verifier layer
  # (`tests/zk/groth16/test_verifier.nim`); VkNotLoaded propagation covered at
  # `tests/zk/test_pol.nim` where the singleton lives. Both are pass-through
  # for this layer.

{.pop.}
