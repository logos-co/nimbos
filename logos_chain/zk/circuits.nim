# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## `logos-blockchain-circuits` bundle layout: path helpers and version pin.
## Per-circuit loaders (e.g. `zk/pol.loadVk`) consume these.

{.push raises: [], gcsafe.}

import
  std/[os, strutils],
  results

export results

const ExpectedCircuitsVersion* = "v0.5.1"
  ## Pinned bundle version. Bump requires re-running setup + revalidating
  ## committed test vectors against the new VK.

type
  CircuitsBundleError* {.pure.} = enum
    BundleDirMissing
    VersionFileMissing
    VersionReadFailed
    VersionMismatch

func circuitsVersionPath*(dir: string): string =
  dir / "VERSION"

func polVerificationKeyPath*(dir: string): string =
  dir / "pol" / "verification_key.json"

func zksignVerificationKeyPath*(dir: string): string =
  dir / "signature" / "verification_key.json"

func pocVerificationKeyPath*(dir: string): string =
  dir / "poc" / "verification_key.json"

# Future per-circuit/per-artefact helpers (PoQ; zkey, witness_generator)
# land here as their verifiers/provers ship.

proc verifyCircuitsVersion*(dir: string): Result[void, CircuitsBundleError] =
  ## Startup bundle health check.
  if not dirExists(dir):
    return err(BundleDirMissing)
  let path = circuitsVersionPath(dir)
  if not fileExists(path):
    return err(VersionFileMissing)
  let installed =
    try:
      readFile(path).strip()
    except IOError, OSError:
      return err(VersionReadFailed)
  if installed != ExpectedCircuitsVersion:
    return err(VersionMismatch)
  ok()

{.pop.}
