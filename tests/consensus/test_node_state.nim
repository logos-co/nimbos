# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/os,
  unittest2,
  results,
  stew/io2,
  stew/byteutils,
  ../../logos_chain/core/types,
  ../../logos_chain/node_state

suite "logos_chain/node_state":
  test "default platform-specific relative state directory constants":
    check DefaultDataDirWindows == "Nimbos\\logos_chain_node"
    check DefaultDataDirMac == "Library/Application Support/Nimbos/logos_chain_node"
    check DefaultDataDirLinux == ".local/state/nimbos/logos_chain_node"

  test "loadNodeState on missing directory/file returns none":
    let nonExistentDir = "/tmp/non_existent_nimbos_dir_" & $os.getCurrentProcessId()
    check loadNodeState(nonExistentDir).isNone

  test "saveNodeState auto-creates target directory if missing":
    let newDir = "/tmp/test_node_state_autocreate_" & $os.getCurrentProcessId() / "nested_dir"
    defer: discard io2.removeDir("/tmp/test_node_state_autocreate_" & $os.getCurrentProcessId())

    var sampleId: BlockId
    sampleId[0] = 0x12'u8
    saveNodeState(newDir, lastOnlineTimestampUnix = 1_700_000_500'u64, libBlockId = sampleId)

    let loadedOpt = loadNodeState(newDir)
    check loadedOpt.isSome
    check loadedOpt.get().lastOnlineTimestampUnix == 1_700_000_500'u64

  test "saveNodeState and loadNodeState roundtrip":
    let tmpDir = "/tmp/test_node_state_" & $os.getCurrentProcessId()
    discard io2.createPath(tmpDir, 0o700)
    defer: discard io2.removeDir(tmpDir)

    var sampleId: BlockId
    sampleId[0] = 0xAA'u8
    sampleId[31] = 0xBB'u8

    saveNodeState(tmpDir, lastOnlineTimestampUnix = 1_700_000_000'u64, libBlockId = sampleId)

    let loadedOpt = loadNodeState(tmpDir)
    check loadedOpt.isSome
    let loaded = loadedOpt.get()
    check loaded.lastOnlineTimestampUnix == 1_700_000_000'u64
    check loaded.libBlockId == "aa000000000000000000000000000000000000000000000000000000000000bb"

  test "loadNodeState on corrupted JSON file returns none safely":
    let tmpDir = "/tmp/test_node_state_corrupt_" & $os.getCurrentProcessId()
    discard io2.createPath(tmpDir, 0o700)
    defer: discard io2.removeDir(tmpDir)

    let statePath = tmpDir / NodeStateFileName
    discard io2.writeFile(statePath, "{ invalid_json: true ]")

    let loadedOpt = loadNodeState(tmpDir)
    check loadedOpt.isNone

  test "parseSavedNodeState returns defaults on none":
    var gid: BlockId
    let (lastOnlineOpt, isLibAtGenesis) = parseSavedNodeState(Opt.none(NodeStateRecord), gid)
    check lastOnlineOpt.isNone
    check isLibAtGenesis == true

  test "parseSavedNodeState detects genesis vs advanced LIB":
    var gid: BlockId
    gid[0] = 0x11'u8
    let matchingState = NodeStateRecord(
      lastOnlineTimestampUnix: 1_700_000_123'u64,
      libBlockId: byteutils.toHex(gid),
    )
    let (lastOnline1, isGen1) = parseSavedNodeState(Opt.some(matchingState), gid)
    check lastOnline1 == Opt.some(1_700_000_123'u64)
    check isGen1 == true

    let advancedState = NodeStateRecord(
      lastOnlineTimestampUnix: 1_700_000_456'u64,
      libBlockId: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
    let (lastOnline2, isGen2) = parseSavedNodeState(Opt.some(advancedState), gid)
    check lastOnline2 == Opt.some(1_700_000_456'u64)
    check isGen2 == false

{.pop.}
