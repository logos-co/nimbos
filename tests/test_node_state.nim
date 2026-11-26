# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/os,
  results,
  stew/io2,
  ./testutil,
  ../logos_chain/core/types,
  ../logos_chain/node_state

const NodeStateFileName = "node_state.json"

suite "node_state":
  test "saveNodeState creates nested directory and roundtrips with loadNodeState":
    withTempDir(baseDir, "test_node_state"):
      let nestedDir = baseDir / "state"
      var id1, id2: BlockId
      id1[0] = 0xAA'u8
      id2[31] = 0xBB'u8

      check:
        loadNodeState(nestedDir).isNone
        saveNodeState(nestedDir, lastOnlineTimestampUnix = 1_700_000_000'u64, libBlockId = id1).isOk
        loadNodeState(nestedDir).get == NodeStateRecord(
          lastOnlineTimestampUnix: 1_700_000_000'u64, libBlockId: id1
        )
        # Atomic overwrite updates existing file in place
        saveNodeState(nestedDir, lastOnlineTimestampUnix = 1_700_000_500'u64, libBlockId = id2).isOk
        loadNodeState(nestedDir).get == NodeStateRecord(
          lastOnlineTimestampUnix: 1_700_000_500'u64, libBlockId: id2
        )

  test "loadNodeState returns none on corrupt JSON, unsupported version, or invalid hex":
    withTempDir(tmpDir, "test_node_state_invalid"):
      let statePath = tmpDir / NodeStateFileName
      for badPayload in [
        "{ invalid_json: true ]",
        "{\"version\":99,\"lastOnlineTimestampUnix\":1700000000,\"libBlockId\":\"aa00000000000000000000000000000000000000000000000000000000000000\"}",
        "{\"version\":1,\"lastOnlineTimestampUnix\":1700000000,\"libBlockId\":\"not_a_valid_hex_string\"}",
      ]:
        check:
          io2.writeFile(statePath, badPayload).isOk
          loadNodeState(tmpDir).isNone

{.pop.}
