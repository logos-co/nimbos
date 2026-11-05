# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[os, strutils],
  stew/[byteutils, io2],
  ../testutil,
  ../../logos_chain/conf,
  ../../logos_chain/networking/network

const
  goldenSeed = "e01039077e592ce1c454c5e8ffe2f571f6fad6106ff0e1895c9a403c126ba80f"
  goldenPubkey = "dc4aec617a8889e651c88997f2c4ba7e606cc553434a526f73109d26aa9d69ac"
  goldenPeerId = "12D3KooWQeJ8CUvQJQ6iMY6yKH49igfH7zrP1qSpqTBeRqTCS4iX"

template peerIdOf(keys: NetKeyPair): string =
  $PeerId.init(keys.pubkey).expect("valid peer id")

suite "networking/net_keys":
  test "golden seed gives the golden pubkey and peer id":
    let keys = netKeysFromSeedHex(goldenSeed).expect("valid seed")
    check:
      byteutils.toHex(keys.pubkey.edkey.data) == goldenPubkey
      peerIdOf(keys) == goldenPeerId

  test "prefix, upper case and whitespace give the golden peer id":
    let
      prefixed = netKeysFromSeedHex("0x" & goldenSeed).expect("0x prefix")
      upper = netKeysFromSeedHex("0X" & goldenSeed.toUpperAscii).expect(
        "0X prefix and upper case")
      padded = netKeysFromSeedHex("  " & goldenSeed & " \n").expect(
        "surrounding whitespace")
    check:
      peerIdOf(prefixed) == goldenPeerId
      peerIdOf(upper) == goldenPeerId
      peerIdOf(padded) == goldenPeerId

  test "wrong length is rejected":
    check:
      netKeysFromSeedHex(goldenSeed[0 ..< 63]).isErr
      netKeysFromSeedHex(goldenSeed & "0").isErr
      netKeysFromSeedHex("0x" & goldenSeed[0 ..< 62]).isErr

  test "non-hex character is rejected":
    check netKeysFromSeedHex("g" & goldenSeed[1 .. ^1]).isErr

  test "readNetKeyFile fails on a missing file":
    check readNetKeyFile(getTempDir() / "nimbos_net_key_missing_3b7e9a1c").isErr

  test "loadNetKeys reads an inline seed":
    let keys = getTestHmacRng().loadNetKeys(
      NetworkConfig(netKey: some(goldenSeed))).expect("inline seed")
    check peerIdOf(keys) == goldenPeerId

  test "loadNetKeys reads a seed file":
    # A per-process name keeps parallel test executors apart.
    let path = getTempDir() / ("nimbos_net_key_test_" & $getCurrentProcessId())
    check io2.writeFile(path, goldenSeed & "\n").isOk
    defer: discard io2.removeFile(path)
    let keys = getTestHmacRng().loadNetKeys(
      NetworkConfig(netKeyFile: some(path))).expect("seed file")
    check peerIdOf(keys) == goldenPeerId

  test "loadNetKeys rejects two sources and randomizes with none":
    let
      rng = getTestHmacRng()
      both = NetworkConfig(
        netKey: some(goldenSeed), netKeyFile: some("unused"))
    check:
      rng.loadNetKeys(both).isErr
      peerIdOf(rng.loadNetKeys(NetworkConfig()).expect("random key")) !=
        peerIdOf(rng.loadNetKeys(NetworkConfig()).expect("random key"))

{.pop.}
