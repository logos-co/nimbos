# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  constantine/math/[arithmetic, io/io_bigints],
  poseidon2/types,
  ../logos_chain/zk/poseidon2/hasher

# Reference values cross-checked against logos-blockchain/zk/poseidon2/src/hasher.rs.
# We go BigInt -> fromBig instead of F.fromDecimal because constantine's FF
# fromDecimal is mis-declared raises:[] and won't compile under strict effect
# tracking — constantine's own tests use this same workaround.

template checkDigest(inputs: openArray[F], decimal: string) =
  let expected = F.fromBig(B.fromDecimal(decimal))
  check Poseidon2Hasher.digest(inputs) == expected

template checkHexDigest(inputs: openArray[F], hexStr: string) =
  let expected = F.fromBig(B.fromHex(hexStr))
  check Poseidon2Hasher.digest(inputs) == expected

template checkHexCompress(left, right: F, hexStr: string) =
  let expected = F.fromBig(B.fromHex(hexStr))
  check Poseidon2Hasher.compress(left, right) == expected

suite "Poseidon2Hasher (BN254)":
  test "digest([0])":
    checkDigest([zero],
      "14440562208246903332530876912784724937356723424375796042690034647976142142243")

  test "digest([1])":
    checkDigest([one],
      "13955187255749411516377601857453481686854514827536340092448578824571923228920")

  test "digest([2])":
    checkDigest([two],
      "9632004710537414903275898870712812796867229507472840228295932832943785232633")

  test "digest([0, 1, 2])":
    checkDigest([zero, one, two],
      "21739021971472524335152491270920095773040444510968189350907442466992269802900")

  # Spec v1.0.2 Annex Test Vectors (common-cryptographic-components.md)
  test "spec v1.0.2 Annex Hash Mode test vectors":
    checkHexDigest([zero], "0x1fed118d9f4466859761f22cad078722b8c4a743b5ebe90443b2dce6bbeb7b23")
    checkHexDigest([one], "0x1eda5b2807bb78c5d061263409295d5115b7793a68c5220e37ea8ab2e94068f8")
    checkHexDigest([zero, zero], "0x20579a2bf857cd36947250ec60f374c1faf02a40130b5fc867c2bde4da940fd2")
    checkHexDigest([one, two], "0x1f36d032e4a519d0fbe1502fd8e4ad5fad61868c72c03f4294589f506bb52b6b")
    checkHexDigest([two, one], "0x26418d3cada2e7ad9e17b50731f6de916c80fc0ef88ea3ea6520dafbd37f4d7b")
    checkHexDigest([one, zero, zero], "0x129e88e8d9ae077e2e750222bc131da8b2268ad957cbf83d2b9beed6b9eed7c2")
    checkHexDigest([zero, zero, one], "0x2a29cf254d2376ef660166c0647bcbed3decee8b3903eadeebecf304cd404dd0")
    checkHexDigest([zero, one, zero, one], "0x793b1db3204a1bbb8cd7d06dac0b8ef98ae2664aa1ed57fccd37baf01682d3d")

  test "spec v1.0.2 Annex Compression Mode test vectors":
    checkHexCompress(zero, zero, "0x2ed1da00b14d635bd35b88ab49390d5c13c90da7e9e3a5f1ea69cd87a0aa3e82")
    checkHexCompress(one, zero, "0x63c4e8cac9a858304f0035b069255b069288c2af698ececf362cd8ec8c96665")
    checkHexCompress(zero, one, "0x222816f2669279d4c256ed2f196e8b0d54df83d35d61811bac36ea4e858483fc")
    checkHexCompress(one, one, "0x277530b5f2b87dfe4535f43bb1998eda77736b4b05d15d983503566743c88031")
