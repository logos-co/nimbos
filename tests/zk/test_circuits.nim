# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/[os, times],
  unittest2,
  stew/io2,
  ../../logos_chain/zk/circuits

proc uniqueTmpDir(tag: string): string =
  # Per-test unique subdir under the system temp dir; OS cleans up eventually.
  # No teardown — keeps test bodies focused on the assertion.
  getTempDir() / ("nimbos_circuits_" & tag & "_" & $epochTime())

suite "zk/circuits — path derivations":
  test "circuitsVersionPath joins <dir>/VERSION":
    check circuitsVersionPath("/foo") == "/foo" / "VERSION"

  test "polVerificationKeyPath joins <dir>/pol/verification_key.json":
    check polVerificationKeyPath("/foo") == "/foo" / "pol" / "verification_key.json"

suite "zk/circuits — verifyCircuitsVersion":
  test "rejects missing dir":
    let r = verifyCircuitsVersion(uniqueTmpDir("missing-dir"))
    check r.error == BundleDirMissing

  test "rejects dir without VERSION":
    let dir = uniqueTmpDir("no-version")
    check createPath(dir).isOk
    check verifyCircuitsVersion(dir).error == VersionFileMissing

  test "rejects mismatched VERSION":
    let dir = uniqueTmpDir("bad-version")
    check createPath(dir).isOk
    check io2.writeFile(dir / "VERSION", "v9.9.9").isOk
    check verifyCircuitsVersion(dir).error == VersionMismatch

  test "accepts matching VERSION":
    let dir = uniqueTmpDir("good-version")
    check createPath(dir).isOk
    check io2.writeFile(dir / "VERSION", ExpectedCircuitsVersion).isOk
    check verifyCircuitsVersion(dir).isOk

  test "accepts VERSION with trailing newline":
    # Real bundles ship `echo "v0.4.2" > VERSION` style — has a trailing \n.
    let dir = uniqueTmpDir("nl-version")
    check createPath(dir).isOk
    check io2.writeFile(dir / "VERSION", ExpectedCircuitsVersion & "\n").isOk
    check verifyCircuitsVersion(dir).isOk

{.pop.}
