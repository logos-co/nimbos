# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Test-only helpers for installing the zksign VK and reading the signed
## message out of a committed snarkjs `public.json` fixture.

{.push raises: [].}

import
  stew/io2,
  ../../logos_chain/core/crypto/types,
  ../../logos_chain/core/mantle/proofs,
  ../../logos_chain/zk/zksign,
  ./snarkjs_helpers

proc installZksignVk*(vkPath: string): bool =
  ## Reset + reinstall the zksign VK singleton from a snarkjs
  ## `verification_key.json` on disk.
  zksign.resetVkForTesting()
  let
    vkText = readAllChars(vkPath).valueOr:
      return false
    vk = parseVk(vkText).valueOr:
      return false
  zksign.initVk(vk).isOk

proc loadProof*(proofPath: string): ZkSigProof =
  ## Read a snarkjs `proof.json` and decode to the 128-byte on-wire
  ## ZkSig proof. Raises `AssertionDefect` on read/parse failure since
  ## tests can't recover.
  let proofText = readAllChars(proofPath).valueOr:
    raiseAssert "proof.json unreadable: " & proofPath
  proofJsonToBytes(proofText).valueOr:
    raiseAssert "proof.json malformed: " & proofPath

proc loadTxHash*(publicPath: string): ZkHash =
  ## Last entry of a zksign `public.json` is the signed Fr; return its 32-byte
  ## LE encoding — the wire shape `tryApplyTransfer` expects as `txHash`.
  let
    publicText = readAllChars(publicPath).valueOr:
      raiseAssert "public.json unreadable: " & publicPath
    inputs = publicJsonToInputs(publicText).valueOr:
      raiseAssert "public.json malformed: " & publicPath
  doAssert inputs.len == 33,
    "public.json must have 33 entries: " & publicPath
  encodeFieldElement(inputs[32])

{.pop.}
