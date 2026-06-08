# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import testutils/markdown_reports, unittest2
import
  std/[net, times],
  chronos
import
  ../logos_chain/conf,
  ../logos_chain/networking/network,
  libp2p/switch,
  libp2p/peerid

from std/algorithm import SortOrder, sort
from std/strformat import `&`
from std/tables import OrderedTable, `[]=`, initOrderedTable, mgetOrPut, sort

export unittest2

## Record ``msg`` and mark the current test as failed (unittest2 ``fail()`` is no-arg).
template fail*(msg: string) =
  checkpoint(msg)
  fail()
  # ``unittest2.fail()`` may return when ``abortOnError`` is off; do not fall through.
  raiseAssert msg

type TestDuration = tuple[duration: float, label: string]

var testTimes: seq[TestDuration]
var status = initOrderedTable[string, OrderedTable[string, Status]]()

type TimingCollector = ref object of OutputFormatter

func toFloatSeconds(duration: times.Duration): float =
  duration.inNanoseconds().float / 1_000_000_000.0

method testEnded*(formatter: TimingCollector, testResult: TestResult) =
  {.gcsafe.}: # Lie!
    status.mgetOrPut(testResult.suiteName, initOrderedTable[string, Status]())[
      testResult.testName
    ] =
      case testResult.status
      of TestStatus.OK: Status.OK
      of TestStatus.FAILED: Status.Fail
      of TestStatus.SKIPPED: Status.Skip
    testTimes.add (testResult.duration.toFloatSeconds, testResult.testName)

proc summarizeLongTests*(name: string) =
  # TODO clean-up and make machine-readable/storable the output
  sort(testTimes, system.cmp, SortOrder.Descending)

  try:
    echo ""
    echo "10 longest individual test durations"
    echo "------------------------------------"
    for i, item in testTimes:
      echo &"{item.duration:6.2f}s for {item.label}"
      if i >= 10:
        break

    status.sort do(
      a: (string, OrderedTable[string, Status]),
      b: (string, OrderedTable[string, Status])
    ) -> int:
      cmp(a[0], b[0])

    generateReport(name, status, width = 90, withTotals = false)
  except IOError, OSError, ValueError:
    raiseAssert getCurrentExceptionMsg()

const TestLoopbackIp* = parseIpAddress("127.0.0.1")

proc waitLibp2pConnected*(sw: Switch, remote: PeerId): Future[bool] {.async.} =
  for i in 0 ..< 150:
    if sw.isConnected(remote):
      return true
    await sleepAsync(chronos.milliseconds(100))
  false

proc makeBootstrapConfs*(listenerPort, dialerPort: Port): tuple[
    confL: LBNodeConf, confD: LBNodeConf,
    rngL: ref HmacDrbgContext, rngD: ref HmacDrbgContext] =
  # TODO(logos-chain-networking): remove NatConfig dependency from test helpers once
  # networking no longer relies on eth/net/nat-config style plumbing.
  let natCfg = NatConfig(hasExtIp: true, extIp: TestLoopbackIp)
  let rngL = HmacDrbgContext.new()
  let rngD = HmacDrbgContext.new()
  (
    confL: LBNodeConf(
      cmd: BNStartUpCmd.lbNode,
      listenAddress: some(TestLoopbackIp),
      nat: natCfg,
      quicPort: listenerPort,
      discv5Enabled: false,
      maxPeers: 8,
      hardMaxPeers: some(8),
      agentString: "p2p-bootstrap-listener",
    ),
    confD: LBNodeConf(
      cmd: BNStartUpCmd.lbNode,
      listenAddress: some(TestLoopbackIp),
      nat: natCfg,
      quicPort: dialerPort,
      discv5Enabled: false,
      maxPeers: 8,
      hardMaxPeers: some(8),
      agentString: "p2p-bootstrap-dialer",
    ),
    rngL: rngL,
    rngD: rngD,
  )

addOutputFormatter(new TimingCollector)
