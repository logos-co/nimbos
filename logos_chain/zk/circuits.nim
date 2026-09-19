# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## `logos-blockchain-circuits` bundle layout: path helpers and version pin.
## Per-circuit loaders (via `zk/util.loadVkFromPath`) consume these.

{.push raises: [], gcsafe.}

import
  std/[os, strutils],
  results

export results

const ExpectedCircuitsVersion* = "v0.5.6"
  ## Pinned bundle version. A bump needs a new setup run, fresh test
  ## vectors, and a new source link in `poq.nim`.

type
  Circuit* {.pure.} = enum
    ## The four circom circuits the bundle ships. `$c` is the bundle
    ## subdirectory; the ZkSig circuit ships as `signature/`.
    Pol = "pol"
    Poq = "poq"
    Poc = "poc"
    Signature = "signature"

  BundleError* {.pure.} = enum
    BundleDirMissing
    VersionFileMissing
    VersionReadFailed
    VersionMismatch

func circuitsVersionPath*(dir: string): string =
  dir / "VERSION"

func verificationKeyPath*(dir: string, c: Circuit): string =
  dir / $c / "verification_key.json"

func provingKeyPath*(dir: string, c: Circuit): string =
  dir / $c / "proving_key.zkey"

func witnessDatPath*(dir: string, c: Circuit): string =
  dir / $c / "witness_generator.dat"

proc verifyCircuitsVersion*(dir: string): Result[void, BundleError] =
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
