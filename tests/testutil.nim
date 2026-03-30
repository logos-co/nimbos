# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import testutils/markdown_reports, unittest2
import
  std/net,
  chronos
import
  ../logos_chain/conf,
  ../logos_chain/networking/eth2_network,
  libp2p/switch,
  libp2p/peerid

from std/algorithm import SortOrder, sort
from std/strformat import `&`
from std/tables import OrderedTable, `[]=`, initOrderedTable, mgetOrPut, sort
import std/times

export unittest2

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
  except CatchableError as exc:
    raiseAssert exc.msg

const TestLoopbackIp* = static(parseIpAddress("127.0.0.1"))

proc waitLibp2pConnected*(sw: Switch, remote: PeerId): Future[bool] {.async.} =
  for i in 0 ..< 150:
    if sw.isConnected(remote):
      return true
    await sleepAsync(chronos.milliseconds(100))
  false

proc makeBootstrapConfs*(listenerPort, dialerPort: Port): tuple[
    confL: LBNodeConf, confD: LBNodeConf,
    rngL: ref HmacDrbgContext, rngD: ref HmacDrbgContext] =
  result.rngL = HmacDrbgContext.new()
  result.rngD = HmacDrbgContext.new()
  # TODO(logos-chain-networking): remove NatConfig dependency from test helpers once
  # networking no longer relies on eth/net/nat-config style plumbing.
  let natCfg = NatConfig(hasExtIp: true, extIp: TestLoopbackIp)
  result.confL.listenAddress = some(TestLoopbackIp)
  result.confL.nat = natCfg
  result.confL.quicPort = listenerPort
  result.confL.discv5Enabled = false
  result.confL.maxPeers = 8
  result.confL.hardMaxPeers = some(8)
  result.confL.agentString = "p2p-bootstrap-listener"
  result.confD.listenAddress = some(TestLoopbackIp)
  result.confD.nat = natCfg
  result.confD.quicPort = dialerPort
  result.confD.discv5Enabled = false
  result.confD.maxPeers = 8
  result.confD.hardMaxPeers = some(8)
  result.confD.agentString = "p2p-bootstrap-dialer"

addOutputFormatter(new TimingCollector)
