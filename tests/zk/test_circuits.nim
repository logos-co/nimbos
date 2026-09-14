# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/[os, strutils],
  unittest2,
  stew/io2,
  ../../logos_chain/zk/circuits,
  ./helpers

const testCircuitsDir = block:
  let testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  testsDir / "../circuits-bundle" / ExpectedCircuitsVersion

suite "zk/circuits — path derivations":
  test "circuitsVersionPath joins <dir>/VERSION":
    check circuitsVersionPath("/foo") == "/foo" / "VERSION"

  test "per-circuit artefact paths use the bundle directory names":
    check dirName(Circuit.Pol) == "pol"
    check dirName(Circuit.Poq) == "poq"
    check dirName(Circuit.Poc) == "poc"
    check dirName(Circuit.Signature) == "signature"
    check verificationKeyPath("/foo", Circuit.Signature) ==
      "/foo" / "signature" / "verification_key.json"
    check provingKeyPath("/foo", Circuit.Pol) == "/foo" / "pol" / "proving_key.zkey"
    check witnessDatPath("/foo", Circuit.Poq) == "/foo" / "poq" / "witness_generator.dat"

suite "zk/circuits — release bundle layout":
  test "verification key paths exist in logos-blockchain-circuits bundle":
    # Requires `make deps` / circuits-install-test (`tests/circuits-bundle/`).
    check verifyCircuitsVersion(testCircuitsDir).isOk
    for c in Circuit:
      check fileExists(verificationKeyPath(testCircuitsDir, c))

  test "prover artefacts exist in the bundle":
    for c in Circuit:
      check fileExists(provingKeyPath(testCircuitsDir, c))
      check fileExists(witnessDatPath(testCircuitsDir, c))

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
