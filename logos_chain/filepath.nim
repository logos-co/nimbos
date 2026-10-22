# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import chronicles
import stew/io2

when defined(windows):
  import stew/[windows/acl, windows/winutils]
  import std/widestrs
  proc moveFileExW(lpExistingFileName, lpNewFileName: pointer, dwFlags: uint32): int32 {.
    importc: "MoveFileExW", header: "<windows.h>", stdcall, sideEffect.}
  const
    MOVEFILE_REPLACE_EXISTING = 0x00000001'u32
    MOVEFILE_WRITE_THROUGH = 0x00000008'u32
else:
  proc posix_rename(oldpath, newpath: cstring): cint {.
    importc: "rename", header: "<stdio.h>", sideEffect.}

type
  ByteChar = byte | char

proc secureCreatePath*(path: string): IoResult[void] =
  when defined(windows):
    let sres = createFoldersUserOnlySecurityDescriptor()
    if sres.isErr():
      error "Could not allocate security descriptor", path = path,
            errorMsg = ioErrorMsg(sres.error), errorCode = $sres.error
      err(sres.error)
    else:
      var sd = sres.get()
      createPath(path, 0o700, secDescriptor = sd.getDescriptor())
  else:
    createPath(path, 0o700)

proc secureWriteFile*[T: ByteChar](path: string,
                                   data: openArray[T]): IoResult[void] =
  when defined(windows):
    let sres = createFilesUserOnlySecurityDescriptor()
    if sres.isErr():
      error "Could not allocate security descriptor", path = path,
            errorMsg = ioErrorMsg(sres.error), errorCode = $sres.error
      err(sres.error())
    else:
      var sd = sres.get()
      let res = writeFile(path, data, 0o600, sd.getDescriptor())
      if res.isErr():
        # writeFile() will not attempt to remove file on failure
        discard removeFile(path)
        err(res.error())
      else:
        ok()
  else:
    let res = writeFile(path, data, 0o600)
    if res.isErr():
      # writeFile() will not attempt to remove file on failure
      discard removeFile(path)
      err(res.error())
    else:
      ok()

proc secureReplaceFile*(src, dst: string): IoResult[void] =
  ## Atomically replaces `dst` with `src` on the same filesystem.
  when defined(windows):
    let
      wsrc = newWideCString(src)
      wdst = newWideCString(dst)
    if moveFileExW(wsrc[0].addr, wdst[0].addr,
                   MOVEFILE_REPLACE_EXISTING or MOVEFILE_WRITE_THROUGH) == 0:
      return err(ioLastError())
    ok()
  else:
    if posix_rename(src.cstring, dst.cstring) != 0:
      return err(ioLastError())
    ok()

{.pop.}
