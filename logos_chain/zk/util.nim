# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Shared Groth16 VK load + singleton install helpers used by per-circuit
## modules (`pol`, `poc`, `zksign`). Each circuit keeps its own `Opt[VKey]` slot;
## these procs own the duplicated I/O and install logic.
##
## Contract for every slot: `installVk` runs on the main thread at startup,
## before any worker is spawned. Per-circuit `verify` is read-only and safe
## to call concurrently afterwards. Per-circuit `resetVkForTesting` clears the
## slot between tests — never call while workers are alive. The `cast(gcsafe)`
## blocks rely on this: under refc the singleton's seq is never mutated and
## never freed, so concurrent reads do no GC operations.

{.push raises: [], gcsafe.}

import
  std/os,
  results,
  ./groth16/[vk_json, verifier]

export VKey, FieldElement, ProofBytesLen, vk_json, verifier, results

type
  VkLoadError* {.pure.} = enum
    VkFileMissing
    VkReadFailed
    VkInvalid
    VkAlreadyLoaded
    VkNotLoaded

proc loadVkFromPath*(path: string): Result[VKey, VkLoadError] =
  ## Read + parse a snarkjs `verification_key.json` at `path`.
  if not fileExists(path):
    return err(VkFileMissing)
  let text =
    try:
      readFile(path)
    except IOError, OSError:
      return err(VkReadFailed)
  let vk = parseVk(text).valueOr:
    return err(VkInvalid)
  ok(vk)

proc installVk*(slot: var Opt[VKey], vk: VKey): Result[void, VkLoadError] =
  ## Install `vk` into `slot`. Reinitialisation returns `VkAlreadyLoaded`.
  ## Callers that pass a module-level singleton must wrap with `cast(gcsafe)`.
  if slot.isSome:
    return err(VkAlreadyLoaded)
  slot = Opt.some(vk)
  ok()

{.pop.}
