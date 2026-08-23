# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[net, times],
  bearssl/rand,
  chronos,
  libp2p/[switch, peerid],
  libp2p/crypto/rng,
  libp2p/crypto/ed25519/ed25519,
  testutils/markdown_reports,
  unittest2,
  ../logos_chain/conf,
  ../logos_chain/networking/network,
  ../logos_chain/core/[types, local_tree],
  ../logos_chain/core/mantle/tx_types,
  ../logos_chain/chain/genesis,
  ../logos_chain/ledger/[pol_verifier, types]

from ../logos_chain/core/mantle/primitives import SlotNumber
from std/algorithm import SortOrder, sort
from std/strformat import `&`
from std/tables import OrderedTable, `[]=`, initOrderedTable, mgetOrPut

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
const TestQuicAnyPort* = Port(0)

template loopbackQuicMultiAddr*(port: Port): string =
  "/ip4/" & $TestLoopbackIp & "/udp/" & $port & "/quic-v1"

template waitUntil*(cond: untyped, timeout: chronos.Duration = chronos.seconds(3)): bool =
  let deadline = Moment.now() + timeout
  var res = false
  while Moment.now() < deadline:
    if cond:
      res = true
      break
    await sleepAsync(chronos.milliseconds(10))
  res

proc createTestNode*(
    agentString: string,
    bootstrapNodes: seq[string] = @[],
    bootstrapTimeout: int = DefaultBootstrapTimeout,
    maxPeers: int = 16,
): LBP2PNode =
  let rng = HmacDrbgContext.new()
  let conf = NetworkConfig(
    listenAddress: some(TestLoopbackIp),
    nat: nat.NatConfig(hasExtIp: true, extIp: TestLoopbackIp),
    quicPort: TestQuicAnyPort,
    maxPeers: maxPeers,
    hardMaxPeers: some(maxPeers),
    agentString: agentString,
    autonatAllowPrivateAddresses: true,
    bootstrapNodes: bootstrapNodes,
    bootstrapTimeout: bootstrapTimeout,
  )
  createLBP2PNode(rng, conf, rng.getRandomNetKeys()).valueOr:
    fail("createLBP2PNode failed for " & agentString & ": " & $error)

proc startTestNode*(
    agentString: string,
    bootstrapNodes: seq[string] = @[],
    bootstrapTimeout: int = DefaultBootstrapTimeout,
    maxPeers: int = 16,
): Future[LBP2PNode] {.async.} =
  let node = createTestNode(agentString, bootstrapNodes, bootstrapTimeout, maxPeers)
  await node.startListening()
  node

proc fullAddress*(node: LBP2PNode): string =
  let addrs = node.switch.peerInfo.fullAddrs().valueOr:
    fail("peerInfo.fullAddrs failed: " & $error)
  if addrs.len == 0:
    fail("node has no full addrs")
  $addrs[0]

const
  ## Deterministic unreachable loopback QUIC endpoint for testing dial failures and timeouts.
  ## Multiaddress: /ip4/127.0.0.1/udp/59999/quic-v1/p2p/{peerId}
  ## The PeerId (12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN) was derived from
  ## a valid Ed25519 public key generated via HmacDrbgContext([42'u8]).
  DeadBootstrapAddress* =
    "/ip4/127.0.0.1/udp/59999/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"

func minimalSignedTx*(): SignedMantleTx =
  SignedMantleTx(
    tx: MantleTx(ops: @[]),
    opProofs: @[],
  )

let testBlockKeyPair = block:
  var rngRef = new(HmacDrbgContext)
  rngRef[] = HmacDrbgContext.init([9'u8])
  EdKeyPair.random(newBearSslRng(rngRef))

proc childBlock*(
    parentHdr: Header,
    parentId: BlockId,
    slot: SlotNumber,
    txs: openArray[SignedMantleTx],
): Block =
  var proofOfLeadership = parentHdr.proofOfLeadership
  proofOfLeadership.leaderKey = testBlockKeyPair.pubkey

  let h = initHeader(
    bedrockVersion = parentHdr.bedrockVersion,
    parentBlock = parentId,
    slot = slot,
    txs = txs,
    proofOfLeadership = proofOfLeadership,
  )
  let sig = testBlockKeyPair.seckey.sign(blockId(h))
  initBlock(h, signature = sig, txs = txs)

proc extendChainAfterGenesis*(
    tree: LocalTree, genesis: Block, extraBlocks: int,
): BlockId =
  ## Add ``extraBlocks`` descendants on top of ``genesis``; return the tip id.
  # Empty blocks: these exercise sync only, and a tx that can't cover its gas
  # fails ledger validation.
  var parentHdr = genesis.header
  var parentId = blockId(genesis.header)
  for slot in 1 .. extraBlocks:
    let blk = childBlock(parentHdr, parentId, SlotNumber(slot.uint64), [])
    check tree.addBlockToTree(blk)
    parentHdr = blk.header
    parentId = blockId(blk.header)
  parentId

type BootstrapPeers* = object
  listener*, dialer*: LBP2PNode
  listenerPeerId*: PeerId

proc createBootstrapPeers*(): Future[BootstrapPeers] {.async.} =
  let listener = await startTestNode("p2p-bootstrap-listener", maxPeers = 8)
  let listenerPeerId = listener.switch.peerInfo.peerId
  let dialer = await startTestNode("p2p-bootstrap-dialer", @[listener.fullAddress()], maxPeers = 8)

  BootstrapPeers(
    listener: listener,
    dialer: dialer,
    listenerPeerId: listenerPeerId,
  )

proc mockVerifyLeaderProof*(
    proof: ProofOfLeadership, public: LeaderPublic
): Result[bool, PolLoadError] =
  ok(true)

addOutputFormatter(new TimingCollector)
