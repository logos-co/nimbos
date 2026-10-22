# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
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

const
  NodeStateFileName = "node_state.json"
  NodeStateVersion = 1'u32

type
  NodeStateRecord* = object
    lastOnlineTimestampUnix*: uint64
    libBlockId*: BlockId
      ## Latest immutable block (LIB) anchor.
      ## TODO: Once block-tree persistence is implemented, this anchor is verified
      ## against the persisted block tree on startup.

  NodeStateJson = object
    version: uint32
    lastOnlineTimestampUnix: uint64
    libBlockId: string

proc loadNodeState*(dataDir: string): Opt[NodeStateRecord] =
  if dataDir.len == 0:
    return Opt.none(NodeStateRecord)
  let
    path = dataDir / NodeStateFileName
    bytes = io2.readAllBytes(path).valueOr:
      trace "No existing node state file found to load", path
      return Opt.none(NodeStateRecord)
  try:
    let decoded = Json.decode(string.fromBytes(bytes), NodeStateJson)
    if decoded.version != NodeStateVersion:
      warn "Unsupported node state file schema version; ignoring saved state",
        path, version = decoded.version, expected = NodeStateVersion
      return Opt.none(NodeStateRecord)
    let libBlockId = hexToByteArrayStrict[32](decoded.libBlockId)
    Opt.some(NodeStateRecord(
      lastOnlineTimestampUnix: decoded.lastOnlineTimestampUnix,
      libBlockId: libBlockId,
    ))
  except CatchableError as exc:
    warn "Corrupted node state file; ignoring saved state", path, error = exc.msg
    Opt.none(NodeStateRecord)

proc saveNodeState*(
    dataDir: string,
    lastOnlineTimestampUnix: uint64,
    libBlockId: BlockId,
): Result[void, string] =
  if dataDir.len == 0:
    return err("Failed to save node state: dataDir must not be empty")
  let
    path = dataDir / NodeStateFileName
    record = NodeStateJson(
      version: NodeStateVersion,
      lastOnlineTimestampUnix: lastOnlineTimestampUnix,
      libBlockId: byteutils.toHex(libBlockId),
    )
    payload = try:
      Json.encode(record)
    except CatchableError as exc:
      return err("Failed to encode node state to JSON: " & exc.msg)

  let createRes = secureCreatePath(dataDir)
  if createRes.isErr():
    return err("Failed to create node state data directory: " & ioErrorMsg(createRes.error))

  let
    tmpPath = dataDir / (NodeStateFileName & ".tmp")
    writeRes = secureWriteFile(tmpPath, payload)
  if writeRes.isErr():
    return err("Failed to write node state temporary file: " & ioErrorMsg(writeRes.error))

  secureReplaceFile(tmpPath, path).isOkOr:
    discard io2.removeFile(tmpPath)
    return err("Failed to move node state file into place: " & ioErrorMsg(error))
  ok()

func parseSavedNodeState*(
    savedState: Opt[NodeStateRecord],
    genesisId: BlockId,
): tuple[lastOnlineOpt: Opt[uint64], isLibAtGenesis: bool] =
  let state = savedState.valueOr:
    return (Opt.none(uint64), true)
  (Opt.some(state.lastOnlineTimestampUnix), state.libBlockId == genesisId)

{.pop.}
