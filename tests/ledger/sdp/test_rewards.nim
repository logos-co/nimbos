# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/tables,
  unittest2,
  results,
  ./test_helpers,
  ../../../logos_chain/core/crypto/hashing,
  ../../../logos_chain/ledger/sdp/rewards

suite "ledger/sdp/rewards":
  test "rewardOpId hashes the one-byte service tag and u32 LE epoch":
    check rewardOpId(ServiceType.bn, 5) ==
      blake2b256Hash([byte 0, 5, 0, 0, 0])

  test "rewardOpId differs across epochs":
    check rewardOpId(ServiceType.bn, 1) != rewardOpId(ServiceType.bn, 2)

  test "distributeRewards mints in ascending numeric zk_id order":
    # 257 encodes LE as [1, 1, 0, ...]; byte-wise lexicographic order from
    # the low byte would place it before 2 — numeric order must not.
    let
      zkSmall = frFromBytesLE([byte 2]).get
      zkLarge = frFromBytesLE([byte 1, 1]).get
    var rewards = initTable[ZkPublicKey, Value]()
    rewards[zkLarge] = 40
    rewards[zkSmall] = 30
    let minted = distributeRewards(rewards, 3, ServiceType.bn)
    check minted.len == 2
    check minted[0].note.zkPublicKey == zkSmall
    check minted[0].note.value == 30
    check minted[0].outputIndex == 0
    check minted[1].note.zkPublicKey == zkLarge
    check minted[1].outputIndex == 1
    check minted[0].opId == minted[1].opId
    check minted[0].opId == rewardOpId(ServiceType.bn, 3)

  test "distributeRewards filters zero rewards before indexing":
    var rewards = initTable[ZkPublicKey, Value]()
    rewards[frFromBytesLE([byte 1]).get] = 0
    rewards[frFromBytesLE([byte 2]).get] = 7
    let minted = distributeRewards(rewards, 1, ServiceType.bn)
    check minted.len == 1
    check minted[0].outputIndex == 0
    check minted[0].note.value == 7

  test "distributeRewards over an empty map mints nothing":
    check distributeRewards(
      initTable[ZkPublicKey, Value](), 1, ServiceType.bn).len == 0

{.pop.}
