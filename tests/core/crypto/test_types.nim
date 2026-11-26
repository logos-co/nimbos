# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  stew/byteutils,
  ../../../logos_chain/core/crypto/types

suite "core/crypto/types":
  test "encodeLe infers output width from unsigned input type":
    let
      le16 = encodeLe(0x0123'u16)
      le32 = encodeLe(0x0123_4567'u32)
      le64 = encodeLe(0x0123_4567_89AB_CDEF'u64)
    check:
      le16.len == 2
      le32.len == 4
      le64.len == 8
      le16 == [0x23'u8, 0x01'u8]
      le32 == [0x67'u8, 0x45'u8, 0x23'u8, 0x01'u8]

  test "encodeLe explicit generic and inferred forms match":
    const
      v16 = 0xBEEF'u16
      v32 = 0xDEAD_BEEF'u32
      v64 = 0x0123_4567_89AB_CDEF'u64
    check:
      encodeLe(v16) == encodeLe[uint16](v16)
      encodeLe(v32) == encodeLe[uint32](v32)
      encodeLe(v64) == encodeLe[uint64](v64)

  test "encodeLe uint64 little-endian":
    let le = encodeLe(0x0102_0304_0506_0708'u64)
    check:
      le[0] == 8'u8
      le[7] == 1'u8

  test "encodeU32LeLenPrefixed length then bytes":
    let s = encodeU32LeLenPrefixed([9'u8, 8'u8, 7'u8]).get
    check:
      s.len == 4 + 3
      s[0] == 3'u8
      s[4] == 9'u8
      s[5] == 8'u8
      s[6] == 7'u8

  test "encodeFieldElement round-trips canonical LE bytes":
    var bytes: array[32, byte]
    bytes[0] = 0x11'u8
    check:
      encodeFieldElement(decodeFieldElement(bytes).get) == bytes
      encodeHash32(bytes) == bytes

  test "decode helpers return DecodingError on malformed input":
    check:
      decodeFieldElement([1'u8, 2'u8]).error == DecodingError.UnexpectedEnd
      decodeU32LeLenPrefixed([10'u8, 0'u8, 0'u8, 0'u8, 1'u8]).error == DecodingError.BufferExceeded

  test "verifyStrict matches the strict speccheck verdicts":
    # The 12 cases of "Taming the many EdDSAs" (Chalkias et al.). The verdicts
    # are the strict row of the published table, which CCC 1.2.0 requires:
    # https://github.com/novifinancial/ed25519-speccheck/blob/65519336fda78a3d016e947df6d82848aca0c9da/README.md
    # Only case 3 has `S < ℓ`, a key and `R` not of small order, and a valid
    # equation.
    const cases = [
      ("8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a" &
          "0000000000000000000000000000000000000000000000000000000000000000", false),
      ("9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43" &
          "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04", false),
      ("aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa" &
          "8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e", false),
      ("9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f" &
          "87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009", true),
      ("e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed512" &
          "5ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09", false),
      ("e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7" &
          "e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405", false),
      ("85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e" &
          "547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514", false),
      ("85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa1942" &
          "7e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22", false),
      ("9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" &
          "03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f", false),
      ("9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" &
          "ca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908", false),
      ("e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc" &
          "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04", false),
      ("39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc" &
          "a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04", false),
    ]
    for i, (message, key, signature, valid) in cases:
      checkpoint "case " & $i
      check verifyStrict(
        EdSignature(data: hexToByteArray[64](signature)),
        hexToSeqByte(message),
        EdPublicKey(data: hexToByteArray[32](key))) == valid

{.pop.}
