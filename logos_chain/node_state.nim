# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Persisted node runtime state tracking last online timestamp and immutable anchor.

{.push raises: [], gcsafe.}

import
  std/os,
  chronicles,
  results,
  stew/io2,
  stew/byteutils,
  json_serialization,
  ./core/types,
  ./filepath

logScope:
  topics = "node_state"

type
  NodeStateRecord* = object
    lastOnlineTimestampUnix*: uint64
    libBlockId*: string

const
  NodeStateFileName* = "node_state.json"
  DefaultNodeNamespace = "logos_chain_node"

  ## Platform-specific default relative state directories
  DefaultDataDirWindows* = "Nimbos\\" & DefaultNodeNamespace
  DefaultDataDirMac* = "Library/Application Support/Nimbos/" & DefaultNodeNamespace
  DefaultDataDirLinux* = ".local/state/nimbos/" & DefaultNodeNamespace

proc defaultNodeDataDir(): string =
  ## Returns platform-aware default data directory:
  ## - Windows: %LOCALAPPDATA%\Nimbos\logos_chain_node
  ## - macOS:   ~/Library/Application Support/Nimbos/logos_chain_node
  ## - Linux:   $XDG_STATE_HOME/nimbos/logos_chain_node (~/.local/state/...)
  when defined(windows):
    let base = os.getEnv("LOCALAPPDATA", os.getEnv("APPDATA"))
    base / DefaultDataDirWindows
  elif defined(macos) or defined(macosx):
    os.getHomeDir() / DefaultDataDirMac
  else:
    let xdg = os.getEnv("XDG_STATE_HOME")
    if xdg.len > 0:
      xdg / "nimbos" / DefaultNodeNamespace
    else:
      os.getHomeDir() / DefaultDataDirLinux

proc loadNodeState*(dataDir: string): Opt[NodeStateRecord] =
  let targetDir = if dataDir.len > 0: dataDir else: defaultNodeDataDir()
  let path = targetDir / NodeStateFileName
  let bytes = io2.readAllBytes(path).valueOr:
    trace "No existing node state file found to load", path
    return Opt.none(NodeStateRecord)
  try:
    let record = Json.decode(string.fromBytes(bytes), NodeStateRecord)
    Opt.some(record)
  except CatchableError as exc:
    warn "Corrupted node state file; ignoring saved state", path, error = exc.msg
    Opt.none(NodeStateRecord)

proc saveNodeState*(
    dataDir: string,
    lastOnlineTimestampUnix: uint64,
    libBlockId: BlockId,
) =
  let targetDir = if dataDir.len > 0: dataDir else: defaultNodeDataDir()
  let path = targetDir / NodeStateFileName
  let record = NodeStateRecord(
    lastOnlineTimestampUnix: lastOnlineTimestampUnix,
    libBlockId: byteutils.toHex(libBlockId),
  )
  let payload = try:
    Json.encode(record)
  except CatchableError as exc:
    warn "Failed to encode node state to JSON", error = exc.msg
    return

  let createRes = secureCreatePath(targetDir)
  if createRes.isErr():
    warn "Failed to create node state data directory", path = targetDir, error = ioErrorMsg(createRes.error)
    return

  let tmpPath = targetDir / (NodeStateFileName & ".tmp")
  let writeRes = secureWriteFile(tmpPath, payload)
  if writeRes.isErr():
    warn "Failed to write node state temporary file", path = tmpPath, error = ioErrorMsg(writeRes.error)
    return

  try:
    os.moveFile(tmpPath, path)
  except CatchableError as exc:
    warn "Failed to move node state file into place", tmpPath, path, error = exc.msg
    discard io2.removeFile(tmpPath)
  except Exception as exc:
    warn "Failed to move node state file into place", tmpPath, path, error = exc.msg
    discard io2.removeFile(tmpPath)

func parseSavedNodeState*(
    savedState: Opt[NodeStateRecord],
    genesisId: BlockId,
): tuple[lastOnlineOpt: Opt[uint64], isLibAtGenesis: bool] =
  let state = savedState.valueOr:
    return (Opt.none(uint64), true)
  (Opt.some(state.lastOnlineTimestampUnix), state.libBlockId == byteutils.toHex(genesisId))

{.pop.}
