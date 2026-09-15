# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Shared fixtures for the prover-side suites: bundle artefacts, the witness
## inputs behind each committed reference proof, and one lazily created
## `Prover` for the whole test binary. Each circuit is driven only with its
## own `.dat` (see `witness_gen`).

{.push raises: [].}

import
  std/[json, os, strutils],
  stew/io2,
  taskpools,
  ../../logos_chain/core/utils,
  ../../logos_chain/zk/[circuits, pol_lottery, prover, witness_gen],
  ./[helpers, prover_fixture_inputs, snarkjs_helpers, wtns_helpers]

export prover, helpers, prover_fixture_inputs, snarkjs_helpers, wtns_helpers

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  testCircuitsDir* = testsDir.parentDir / "circuits-bundle" / ExpectedCircuitsVersion
  fixturesDir = testsDir.parentDir / "fixtures"
  ZkSignFixtureMsg* =
    "4638531576864525781488466586415560847030933032030532999162151560076355183707"
    ## Message the committed zksign fixture signs with `sks = [1, 0 × 31]`.
  PoqCoreFixtureQuota* = 15'u64
    ## `core_quota` of the committed core-branch fixture. The key index the
    ## fixture used is not recorded; `poqCoreFixtureIndex` recovers it.

func fr*(decimal: string): FieldElement =
  frFromDecimal(decimal).expect("fixture decimal is a field element")

proc readBundleFile*(path: string): seq[byte] =
  readAllBytes(path).expect("bundle file readable: " & path)

proc readText*(path: string): string =
  readAllChars(path).expect("text file readable: " & path)

proc fixtureDir*(c: Circuit): string =
  fixturesDir / (if c == Circuit.Signature: "zksign" else: dirName(c))

proc fixtureSignals*(c: Circuit): seq[FieldElement] =
  ## Public signals of the committed reference proof for `c`.
  let name = if c == Circuit.Poq: "public_core.json" else: "public.json"
  publicJsonToInputs(readText(fixtureDir(c) / name)).expect("fixture public parses")

proc zksignFixtureInput*(): ZkSignWitnessInput =
  var input = ZkSignWitnessInput(msg: fr(ZkSignFixtureMsg))
  input.secretKeys[0] = fr("1")
  input

proc polFixtureInput*(): PolWitnessInput =
  let lottery = lottery_constants(
    NonNegativeRatio(num: 1, den: 10), PolFixtureTotalStake).expect("supported f")
  var input = PolWitnessInput(
    slotNumber: PolFixtureSlot,
    epochNonce: fr(PolFixtureEpochNonce),
    lottery0: lottery.t0,
    lottery1: lottery.t1,
    agedRoot: fr(PolFixtureAgedRoot),
    latestRoot: fr(PolFixtureLatestRoot),
    leaderPk1: fr(PolFixtureLeaderPk1),
    leaderPk2: fr(PolFixtureLeaderPk2),
    noteValue: PolFixtureNoteValue,
    noteTxHash: fr(PolFixtureNoteTxHash),
    noteOutputNumber: PolFixtureNoteOutputNumber,
    secretKey: fr(PolFixtureSecretKey))
  for i in 0 ..< TreeDepth:
    input.agedPath.siblings[i] = fr(PolFixtureAgedPath[i])
    input.agedPath.selectors[i] = PolFixtureAgedSelectors[i]
    input.latestPath.siblings[i] = fr(PolFixtureLatestPath[i])
    input.latestPath.selectors[i] = PolFixtureLatestSelectors[i]
  input

proc pocFixtureInput*(): PocWitnessInput =
  ## From the reference `sample.input.json` behind the committed PoC proof.
  let j =
    try:
      parseJson(readText(fixtureDir(Circuit.Poc) / "sample.input.json"))
    except JsonParsingError, IOError, OSError, ValueError:
      raiseAssert "poc sample.input.json unreadable"
  var input: PocWitnessInput
  try:
    input.voucherRoot = fr(j["voucher_root"].getStr)
    input.mantleTxHash = fr(j["mantle_tx_hash"].getStr)
    input.secretVoucher = fr(j["secret_voucher"].getStr)
    let
      path = j["voucher_merkle_path"]
      selectors = j["voucher_merkle_path_selectors"]
    doAssert path.len == TreeDepth and selectors.len == TreeDepth
    for i in 0 ..< TreeDepth:
      input.voucherPath.siblings[i] = fr(path[i].getStr)
      input.voucherPath.selectors[i] = selectors[i].getStr != "0"
  except KeyError:
    raiseAssert "poc sample.input.json malformed"
  input

proc poqCoreFixtureInput*(index: uint64): PoqWitnessInput =
  ## Core-branch inputs behind `public_core.json`: the chain and common parts
  ## are the fixture's own public signals, the private part comes from the
  ## reference implementation's fixture function.
  let signals = fixtureSignals(Circuit.Poq)
  doAssert signals.len == PoqPublicSignals
  doAssert signals[3] == fr(PoqCoreFixtureRoot), "fixture root matches the private path"
  var input = PoqWitnessInput(
    coreRoot: signals[3],
    polLedgerAged: signals[5],
    polEpochNonce: signals[9],
    polT0: signals[10],
    polT1: signals[11],
    coreQuota: PoqCoreFixtureQuota,
    leaderQuota: 1,
    powQuota: 1,
    kPartOne: signals[6],
    kPartTwo: signals[7],
    selector: PoqSelector.Core,
    index: index,
    powBlendDifficulty: signals[8],
    coreSk: fr(PoqCoreFixtureSk))
  for i in 0 ..< CoreTreeHeight:
    input.corePath.siblings[i] = fr(PoqCoreFixturePath[i])
    input.corePath.selectors[i] = PoqCoreFixtureSelectors[i]
  input

proc witnessValues*(c: Circuit, json: string): seq[FieldElement] =
  ## Run the bundle witness generator for `c` with its own `.dat`.
  let
    dat = readBundleFile(witnessDatPath(testCircuitsDir, c))
    wtns = generateWitness(c, dat, json).valueOr:
      raiseAssert "witness generation failed: " & $error.kind & " " &
        messageString(error.message)
  decodeWtns(wtns).expect("wtns decodes")

var poqIndexCache: Opt[uint64]

proc poqCoreFixtureIndex*(): uint64 =
  ## The key index behind `public_core.json`: the one value below the quota
  ## whose witness yields the fixture's key nullifier. Computed once.
  if poqIndexCache.isNone:
    let expected = fixtureSignals(Circuit.Poq)[0]
    for index in 0'u64 ..< PoqCoreFixtureQuota:
      let values = witnessValues(Circuit.Poq, toInputsJson(poqCoreFixtureInput(index)))
      if values[1] == expected:
        poqIndexCache = Opt.some(index)
        break
    doAssert poqIndexCache.isSome, "no key index reproduces the fixture nullifier"
  poqIndexCache.get

var
  sharedPool: Taskpool
  sharedProver: Prover

proc testPool*(): Taskpool =
  ## One two-thread pool for the whole test binary.
  if sharedPool == nil:
    sharedPool =
      try:
        Taskpool.new(numThreads = 2)
      except CatchableError as exc:
        raiseAssert "taskpool creation failed: " & exc.msg
  sharedPool

proc testProver*(): Prover =
  ## One `Prover` over the test bundle for the whole test binary. Creating
  ## one loads every proving key, so suites share it.
  if sharedProver == nil:
    sharedProver = Prover.new(testCircuitsDir, testPool()).expect("test prover")
  sharedProver

proc installFixtureVks*() =
  ## Install every circuit's VK from the test bundle so `verify` works.
  pol.resetVkForTesting()
  poq.resetVkForTesting()
  poc.resetVkForTesting()
  zksign.resetVkForTesting()
  pol.loadAndInitVk(testCircuitsDir).expect("pol vk")
  poq.loadAndInitVk(testCircuitsDir).expect("poq vk")
  poc.loadAndInitVk(testCircuitsDir).expect("poc vk")
  zksign.loadAndInitVk(testCircuitsDir).expect("zksign vk")

{.pop.}
