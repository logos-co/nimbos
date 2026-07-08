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
  ../../logos_chain/core/mantle/proofs,
  ../../logos_chain/ledger/poc_verifier,
  ../../logos_chain/zk/poc,
  ../../logos_chain/zk/poseidon2/hasher,
  ../zk/snarkjs_helpers

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  fixtureVk = testsDir / "../fixtures/poc/verification_key.json"
  fixtureProof = testsDir / "../fixtures/poc/proof.json"
  fixturePublic = testsDir / "../fixtures/poc/public.json"

func toProofOfClaimPublic(s: openArray[FieldElement]): ProofOfClaimPublic =
  doAssert s.len == 3
  ProofOfClaimPublic(
    voucherNullifier: s[0].toBytes(),
    mantleTxHash: s[1].toBytes(),
    voucherRoot: s[2].toBytes(),
  )

suite "ledger/poc_verifier":
  var
    claimProof: ProofOfClaimProof
    public: ProofOfClaimPublic

  setup:
    poc.resetVkForTesting()
    let vkText = readAllChars(fixtureVk).valueOr:
      check false
      return
    let vk = parseVk(vkText).valueOr:
      check false
      return
    check poc.initVk(vk).isOk
    let proofText = readAllChars(fixtureProof).valueOr:
      check false
      return
    let publicText = readAllChars(fixturePublic).valueOr:
      check false
      return
    claimProof = proofJsonToBytes(proofText).valueOr:
      check false
      return
    let inputsSeq = publicJsonToInputs(publicText).valueOr:
      check false
      return
    public = toProofOfClaimPublic(inputsSeq)

  test "real fixture accepted end-to-end":
    let r = verifyProofOfClaim(claimProof, public)
    check r.isOk and r.get

  test "rejects wrong mantle tx hash":
    var badPublic = public
    badPublic.mantleTxHash = public.voucherRoot
    let r = verifyProofOfClaim(claimProof, badPublic)
    check r.isOk and not r.get

{.pop.}
