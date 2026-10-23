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
  unittest2,
  results,
  stew/io2,
  ./testutil,
  ../logos_chain/core/types,
  ../logos_chain/node_state

const NodeStateFileName = "node_state.json"

suite "node_state":
  test "loadNodeState on empty directory string returns none":
    check loadNodeState("").isNone

  test "saveNodeState on empty directory string returns error":
    var sampleId: BlockId
    check saveNodeState("", lastOnlineTimestampUnix = 1_700_000_000'u64, libBlockId = sampleId).isErr

  test "loadNodeState on missing directory/file returns none":
    let nonExistentDir = os.getTempDir() / ("non_existent_nimbos_dir_" & $os.getCurrentProcessId())
    check loadNodeState(nonExistentDir).isNone

  test "saveNodeState auto-creates target directory if missing":
    withTempDir(baseDir, "test_node_state_autocreate"):
      let newDir = baseDir / "nested_dir"
      var sampleId: BlockId
      sampleId[0] = 0x12'u8
      check saveNodeState(newDir, lastOnlineTimestampUnix = 1_700_000_500'u64, libBlockId = sampleId).isOk

      let loaded = loadNodeState(newDir).get
      check:
        loaded.lastOnlineTimestampUnix == 1_700_000_500'u64
        loaded.libBlockId == sampleId

  test "saveNodeState and loadNodeState roundtrip":
    withTempDir(tmpDir, "test_node_state"):
      var sampleId: BlockId
      sampleId[0] = 0xAA'u8
      sampleId[31] = 0xBB'u8

      check saveNodeState(tmpDir, lastOnlineTimestampUnix = 1_700_000_000'u64, libBlockId = sampleId).isOk

      let loaded = loadNodeState(tmpDir).get
      check:
        loaded.lastOnlineTimestampUnix == 1_700_000_000'u64
        loaded.libBlockId == sampleId

  test "loadNodeState on corrupted JSON file returns none safely":
    withTempDir(tmpDir, "test_node_state_corrupt"):
      let statePath = tmpDir / NodeStateFileName
      check io2.writeFile(statePath, "{ invalid_json: true ]").isOk

      let loadedOpt = loadNodeState(tmpDir)
      check loadedOpt.isNone

  test "loadNodeState on unsupported schema version returns none":
    withTempDir(tmpDir, "test_node_state_version"):
      let statePath = tmpDir / NodeStateFileName
      check io2.writeFile(
        statePath,
        "{\"version\":99,\"lastOnlineTimestampUnix\":1700000000,\"libBlockId\":\"aa00000000000000000000000000000000000000000000000000000000000000\"}"
      ).isOk

      let loadedOpt = loadNodeState(tmpDir)
      check loadedOpt.isNone

  test "loadNodeState parses uppercase hex libBlockId successfully":
    withTempDir(tmpDir, "test_node_state_upperhex"):
      var sampleId: BlockId
      sampleId[0] = 0xAB'u8
      sampleId[31] = 0xCD'u8

      let statePath = tmpDir / NodeStateFileName
      check io2.writeFile(
        statePath,
        "{\"version\":1,\"lastOnlineTimestampUnix\":1700000789,\"libBlockId\":\"AB000000000000000000000000000000000000000000000000000000000000CD\"}"
      ).isOk

      let loaded = loadNodeState(tmpDir).get
      check loaded.libBlockId == sampleId

  test "loadNodeState on corrupted BlockId hex in JSON returns none safely":
    withTempDir(tmpDir, "test_node_state_badhex"):
      let statePath = tmpDir / NodeStateFileName
      check io2.writeFile(
        statePath,
        "{\"version\":1,\"lastOnlineTimestampUnix\":1700000000,\"libBlockId\":\"not_a_valid_hex_string\"}"
      ).isOk

      let loadedOpt = loadNodeState(tmpDir)
      check loadedOpt.isNone

  test "parseSavedNodeState returns defaults on none":
    var gid: BlockId
    let (lastOnlineOpt, isLibAtGenesis) = parseSavedNodeState(Opt.none(NodeStateRecord), gid)
    check:
      lastOnlineOpt.isNone
      isLibAtGenesis == true

  test "parseSavedNodeState detects genesis vs advanced LIB":
    var gid: BlockId
    gid[0] = 0x11'u8
    let matchingState = NodeStateRecord(
      lastOnlineTimestampUnix: 1_700_000_123'u64,
      libBlockId: gid,
    )
    let (lastOnline1, isGen1) = parseSavedNodeState(Opt.some(matchingState), gid)
    check:
      lastOnline1 == Opt.some(1_700_000_123'u64)
      isGen1 == true

    var advancedId: BlockId
    advancedId[0] = 0xFF'u8
    let advancedState = NodeStateRecord(
      lastOnlineTimestampUnix: 1_700_000_456'u64,
      libBlockId: advancedId,
    )
    let (lastOnline2, isGen2) = parseSavedNodeState(Opt.some(advancedState), gid)
    check:
      lastOnline2 == Opt.some(1_700_000_456'u64)
      isGen2 == false

{.pop.}
