# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[net, sequtils, times],
  bearssl/rand,
  chronos,
  libp2p/[switch, builders, peerid, multiaddress],
  libp2p/crypto/rng,
  libp2p/crypto/ed25519/ed25519,
  stew/[byteutils, endians2],
  testutils/markdown_reports,
  unittest2,
  ../logos_chain/conf,
  ../logos_chain/networking/network,
  ../logos_chain/core/types,
  ../logos_chain/core/mantle/[operations, tx_types, tx_hashing],
  ../logos_chain/chain/block_processor,
  ./core/mantle/test_helpers

from ../logos_chain/core/crypto/types import encodeFieldElement
from ../logos_chain/core/mantle/primitives import SlotNumber
from std/algorithm import SortOrder, sort, fill
from std/strformat import `&`
from std/tables import OrderedTable, `[]=`, initOrderedTable, mgetOrPut

export unittest2, test_helpers, tx_hashing, createGenesisBlock, ValidBlock, AdmittedBlock

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
  testTimes.sort(system.cmp, SortOrder.Descending)

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

const TestLoopbackIp = parseIpAddress("127.0.0.1")
const TestQuicAnyPort = Port(0)

template loopbackQuicMultiAddr(port: Port): string =
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

let testHmacRng = HmacDrbgContext.new()
let testRng = newBearSslRng(testHmacRng)

proc getTestHmacRng*(): ref HmacDrbgContext =
  {.gcsafe.}:
    testHmacRng

proc getTestRng*(): Rng =
  {.gcsafe.}:
    testRng

proc getRandomNetKeys*(): KeyPair =
  getTestHmacRng().getRandomNetKeys().expect("random network key")

proc getRandomPeerId*(): PeerId =
  PeerId.init(getRandomNetKeys().seckey).expect("valid PeerId")

proc createTestNode*(
    agentString: string,
    bootstrapNodes: seq[string] = @[],
    bootstrapTimeout: int = DefaultBootstrapTimeout,
    maxPeers: int = 16,
    logosNetwork: LogosNetworkKind = LogosNetworkKind.Testnet,
): LBP2PNode =
  let conf = NetworkConfig(
    listenAddress: some(TestLoopbackIp),
    quicPort: TestQuicAnyPort,
    maxPeers: maxPeers,
    hardMaxPeers: some(maxPeers),
    agentString: agentString,
    autonatAllowPrivateAddresses: true,
    bootstrapNodes: bootstrapNodes,
    bootstrapTimeout: bootstrapTimeout,
    logosNetwork: logosNetwork,
  )
  createLBP2PNode(getTestHmacRng(), conf, getRandomNetKeys()).expect("valid test node")

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
  let addrs = node.switch.peerInfo.fullAddrs().expect("valid full addrs")
  if addrs.len == 0:
    fail("node has no full addrs")
  $addrs[0]

func peerAddr*(node: LBP2PNode): PeerAddr =
  PeerAddr(
    peerId: node.switch.peerInfo.peerId,
    addrs: node.switch.peerInfo.addrs,
  )

proc alwaysAllowPeer*(_: PeerAddr): bool {.gcsafe, raises: [].} = true

proc startQuicTestSwitch*(
    keys: KeyPair = getRandomNetKeys(),
    port: Port = TestQuicAnyPort,
    maxConnections: int = 8,
): Future[Switch] {.async.} =
  let sw = SwitchBuilder
    .new()
    .withAddress(MultiAddress.init(loopbackQuicMultiAddr(port)).expect("valid multiaddr"))
    .withRng(getTestRng())
    .withNoise()
    .withQuicTransport()
    .withMaxConnections(maxConnections)
    .withPrivateKey(keys.seckey)
    .build()
  await sw.start()
  sw

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

var defaultMinimalHashedSignedTxCache: HashedSignedMantleTx
var hasDefaultMinimalHashedSignedTxCache = false

proc minimalHashedSignedTx*(): HashedSignedMantleTx =
  {.gcsafe.}:
    if not hasDefaultMinimalHashedSignedTxCache:
      defaultMinimalHashedSignedTxCache = mkHashedSignedTx(minimalSignedTx())
      hasDefaultMinimalHashedSignedTxCache = true
    defaultMinimalHashedSignedTxCache

var defaultMinimalValidSignedTxCache: ValidSignedMantleTx
var hasDefaultMinimalValidSignedTxCache = false

proc minimalValidSignedTx*(): ValidSignedMantleTx =
  {.gcsafe.}:
    if not hasDefaultMinimalValidSignedTxCache:
      defaultMinimalValidSignedTxCache = createValidTxForTest(minimalHashedSignedTx())
      hasDefaultMinimalValidSignedTxCache = true
    defaultMinimalValidSignedTxCache

func testZkPk*(): ZkPublicKey = mkZkPubKey(1)

func txWithPlaceholderProofs*(ops: openArray[Op]): SignedMantleTx =
  ## `ops` with a placeholder proof of the right kind for each.
  SignedMantleTx(
    tx: MantleTx(ops: @ops),
    opProofs: ops.mapIt(defaultOpProofForOpcode(it.opcode).get))

func testGenesisSignedTx*(
    outputs: openArray[Note] = [Note(value: 1000, zkPublicKey: testZkPk())],
    declarations: openArray[DeclarationMessage] = [],
    chainId = "test",
    genesisTime = 0'u32,
    epochNonce = default(FieldElement),
): SignedMantleTx =
  ## Spec-shaped genesis SignedMantleTx (no hash computed).
  let
    inscription =
      @[byte chainId.len] & chainId.toBytes & @(toBytesLE(genesisTime)) &
      @(encodeFieldElement(epochNonce))
    ops = @[
      createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: @[]), outputs: Outputs(notes: @outputs))),
      createChannelInscribeOp(ChannelInscribePayload(
        channelId: default(ChannelId), inscription: inscription,
        parent: default(Parent), signer: DefaultEd25519PublicKey))] &
      declarations.mapIt(createSdpDeclareOp(it))
  txWithPlaceholderProofs(ops)

var defaultGenesisHtxCache: HashedSignedMantleTx
var hasDefaultGenesisHtxCache = false

template isDefaultGenesisArgs(outputs, declarations, chainId, genesisTime, epochNonce): bool =
  declarations.len == 0 and
  chainId == "test" and
  genesisTime == 0'u32 and
  epochNonce == default(FieldElement) and
  outputs.len == 1 and
  outputs[0].value == 1000 and
  outputs[0].zkPublicKey == testZkPk()

proc testGenesisHtx*(
    outputs: openArray[Note] = [Note(value: 1000, zkPublicKey: testZkPk())],
    declarations: openArray[DeclarationMessage] = [],
    chainId = "test",
    genesisTime = 0'u32,
    epochNonce = default(FieldElement),
): HashedSignedMantleTx =
  ## Spec-shaped genesis transaction with precomputed hash: Transfer of `outputs`,
  ## the parameter inscription, then one SdpDeclare per entry; placeholder proofs.
  if isDefaultGenesisArgs(outputs, declarations, chainId, genesisTime, epochNonce):
    {.gcsafe.}:
      if not hasDefaultGenesisHtxCache:
        defaultGenesisHtxCache = createGenesisHtx(testGenesisSignedTx()).expect("valid genesis tx hash")
        hasDefaultGenesisHtxCache = true
      return defaultGenesisHtxCache

  createGenesisHtx(
    testGenesisSignedTx(outputs, declarations, chainId, genesisTime, epochNonce)
  ).expect("valid genesis tx hash")

var defaultValidGenesisTxCache: ValidGenesisMantleTx
var hasDefaultValidGenesisTxCache = false

proc testValidGenesisTx*(
    outputs: openArray[Note] = [Note(value: 1000, zkPublicKey: testZkPk())],
    declarations: openArray[DeclarationMessage] = [],
    chainId = "test",
    genesisTime = 0'u32,
    epochNonce = default(FieldElement),
): ValidGenesisMantleTx =
  if isDefaultGenesisArgs(outputs, declarations, chainId, genesisTime, epochNonce):
    {.gcsafe.}:
      if not hasDefaultValidGenesisTxCache:
        defaultValidGenesisTxCache = createValidGenesisTxForTest(testGenesisHtx())
        hasDefaultValidGenesisTxCache = true
      return defaultValidGenesisTxCache

  createValidGenesisTxForTest(
    testGenesisHtx(outputs, declarations, chainId, genesisTime, epochNonce)
  )

func genesisNoteId*(tx: ValidGenesisMantleTx, index: int): NoteId =
  ## NoteId of output `index` of the genesis Transfer.
  template transfer: untyped = tx.tx.ops[0].payload.transfer
  Utxo(
    opId: opId(transfer).get, outputIndex: uint64(index),
    note: transfer.outputs.notes[index]).id


let testTxKeyPair* = block:
  var rngRef = new(HmacDrbgContext)
  rngRef[] = HmacDrbgContext.init([8'u8])
  EdKeyPair.random(newBearSslRng(rngRef))

func mkChannelInscribeOps(opsCount: int, txIndex: int, signer: Ed25519PublicKey): seq[Op] =
  var ops = newSeqOfCap[Op](opsCount)
  for i in 0 ..< opsCount:
    var cid: ChannelId
    cid[0] = byte(txIndex mod 256)
    cid[1] = byte(txIndex div 256)
    cid[2] = byte(i mod 256)
    cid[3] = byte(i div 256)
    let payload = ChannelInscribePayload(
      channelId: cid,
      inscription: @[byte 0x68, 0x69],
      parent: default(Hash32),
      signer: signer,
    )
    ops.add(createChannelInscribeOp(payload))
  ops

proc hashedSignedTxWithOps*(opsCount: int, txIndex: int): HashedSignedMantleTx =
  let mtx = MantleTx(ops: mkChannelInscribeOps(opsCount, txIndex, testTxKeyPair.pubkey))
  let
    txHash = mantleTxHash(mtx).get
    sig = sign(testTxKeyPair.seckey, txHash)
  var proofs = newSeqOfCap[OpProof](opsCount)
  for _ in 0 ..< opsCount:
    proofs.add(OpProof(kind: opfChannelInscribe, ed25519SigProof: sig))

  createHashedSignedMantleTxForTest(SignedMantleTx(tx: mtx, opProofs: proofs), txHash)

proc validSignedTxWithOps*(opsCount: int, txIndex: int): ValidSignedMantleTx =
  createValidTxForTest(hashedSignedTxWithOps(opsCount, txIndex))

proc mkValidTxWithOps*(opsCount: int, txIndex: int): ValidSignedMantleTx =
  ## Sibling of `validSignedTxWithOps` with placeholder proofs (no Ed25519 signing).
  ## For mempool, proposal, and unit tests that do not verify inscribe signatures.
  let mtx = MantleTx(ops: mkChannelInscribeOps(opsCount, txIndex, testTxKeyPair.pubkey))
  let txHash = mantleTxHash(mtx).get
  var proofs = newSeq[OpProof](opsCount)
  for i in 0 ..< opsCount:
    proofs[i] = OpProof(kind: opfChannelInscribe, ed25519SigProof: DefaultEd25519Signature)

  mkValidTx(createHashedSignedMantleTxForTest(SignedMantleTx(tx: mtx, opProofs: proofs), txHash))

let testBlockKeyPair = block:
  var rngRef = new(HmacDrbgContext)
  rngRef[] = HmacDrbgContext.init([9'u8])
  EdKeyPair.random(newBearSslRng(rngRef))

func initBlock*(
    header: Header,
    signature: Ed25519Signature = DefaultEd25519Signature,
    uncleHeaders: openArray[SignedHeader],
    txs: openArray[HashedSignedMantleTx],
): Block =
  doAssert uncleHeaders.len <= MaxUncles,
    "uncle count exceeds MaxUncles (" & $MaxUncles & "): " & $uncleHeaders.len
  doAssert txs.len <= MaxBlockTxs,
    "block tx count exceeds MaxBlockTxs (" & $MaxBlockTxs & "): " & $txs.len
  Block(
    header: header,
    signature: signature,
    uncleHeaders: UncleHeaders(@uncleHeaders),
    txs: BlockTxs(@txs),
  )

func childBlock*(
    parentHdr: Header,
    parentId: BlockId,
    slot: SlotNumber,
    txs: openArray[HashedSignedMantleTx],
    uncleHeaders: openArray[SignedHeader] = [],
    keyPair: EdKeyPair = testBlockKeyPair,
): Block =
  var proofOfLeadership = parentHdr.proofOfLeadership
  proofOfLeadership.leaderKey = keyPair.pubkey

  let
    h = initHeader(
      bedrockVersion = parentHdr.bedrockVersion,
      parentBlock = parentId,
      slot = slot,
      uncleHeaders = uncleHeaders,
      txs = txs,
      proofOfLeadership = proofOfLeadership,
    )
    sig = keyPair.seckey.sign(blockId(h))
  initBlock(h, signature = sig, uncleHeaders = uncleHeaders, txs = txs)

func childValidBlock*(
    parentHdr: Header,
    parentId: BlockId,
    slot: SlotNumber,
    txs: openArray[ValidSignedMantleTx],
    uncleHeaders: openArray[SignedHeader] = [],
    keyPair: EdKeyPair = testBlockKeyPair,
): ValidBlock =
  var proofOfLeadership = parentHdr.proofOfLeadership
  proofOfLeadership.leaderKey = keyPair.pubkey

  let
    h = initHeader(
      bedrockVersion = parentHdr.bedrockVersion,
      parentBlock = parentId,
      slot = slot,
      uncleHeaders = uncleHeaders,
      txs = txs,
      proofOfLeadership = proofOfLeadership,
    )
    sig = keyPair.seckey.sign(blockId(h))
  createValidBlockForTest(
    header = h,
    signature = sig,
    uncleHeaders = UncleHeaders(@uncleHeaders),
    txs = txs,
  )

func mkChildValidBlock*(
    parentHdr: Header,
    parentId: BlockId,
    slot: SlotNumber,
    txs: openArray[ValidSignedMantleTx] = [],
    uncleHeaders: openArray[SignedHeader] = [],
    keyPair: EdKeyPair = testBlockKeyPair,
): ValidBlock =
  ## Sibling of `childValidBlock` with DefaultEd25519Signature (no Ed25519 signing).
  ## For LocalTree, LCA, and LIB tests where the ValidBlock signature is not verified.
  var proofOfLeadership = parentHdr.proofOfLeadership
  proofOfLeadership.leaderKey = keyPair.pubkey

  let
    h = initHeader(
      bedrockVersion = parentHdr.bedrockVersion,
      parentBlock = parentId,
      slot = slot,
      uncleHeaders = uncleHeaders,
      txs = txs,
      proofOfLeadership = proofOfLeadership,
    )
  createValidBlockForTest(
    header = h,
    signature = DefaultEd25519Signature,
    uncleHeaders = UncleHeaders(@uncleHeaders),
    txs = txs,
  )

func exampleBlockId*(fill: byte): BlockId =
  var blkId: BlockId
  blkId.fill(fill)
  blkId

func mkAdmittedBlock*(slot: uint64, parentBlock: BlockId): AdmittedBlock =
  createAdmittedBlockForTest(Block(header: Header(slot: slot, parentBlock: parentBlock)))

func childProposal*(
    parentHdr: Header,
    parentId: BlockId,
    slot: SlotNumber,
    txs: openArray[ValidSignedMantleTx],
    keyPair: EdKeyPair = testBlockKeyPair,
): Proposal =
  var proofOfLeadership = parentHdr.proofOfLeadership
  proofOfLeadership.leaderKey = keyPair.pubkey

  let
    h = initHeader(
      bedrockVersion = parentHdr.bedrockVersion,
      parentBlock = parentId,
      slot = slot,
      uncleHeaders = [],
      txs = txs,
      proofOfLeadership = proofOfLeadership,
    )
    sig = keyPair.seckey.sign(blockId(h))
  var refs: References
  for i, tx in txs:
    refs[i] = tx.hash
  initProposal(h, [], refs, sig)

func initGenesisBlock*(validGenesisTx: ValidGenesisMantleTx): Block =
  initBlock(
    createGenesisHeader(validGenesisTx),
    signature = DefaultEd25519Signature,
    uncleHeaders = [],
    txs = [validGenesisTx.hashed],
  )

var defaultGenesisBlockCache: ValidBlock
var hasDefaultGenesisBlockCache = false

proc testGenesisBlock*(): ValidBlock =
  {.gcsafe.}:
    if not hasDefaultGenesisBlockCache:
      defaultGenesisBlockCache = createGenesisBlock(testValidGenesisTx())
      hasDefaultGenesisBlockCache = true
    defaultGenesisBlockCache

type BootstrapPeers* = object
  listener*, dialer*: LBP2PNode
  listenerPeerId*: PeerId

proc createBootstrapPeers*(): Future[BootstrapPeers] {.async.} =
  let
    listener = await startTestNode("p2p-bootstrap-listener", maxPeers = 8)
    listenerPeerId = listener.switch.peerInfo.peerId
    dialer = await startTestNode("p2p-bootstrap-dialer", @[listener.fullAddress()], maxPeers = 8)

  BootstrapPeers(
    listener: listener,
    dialer: dialer,
    listenerPeerId: listenerPeerId,
  )

func mkVerifyLeaderProof(
    proof: ProofOfLeadership, public: LeaderPublic
): Result[bool, PolLoadError] =
  ok(true)

func mockVerifyLeaderProof*(
    proof: ProofOfLeadership, public: LeaderPublic
): Result[bool, PolLoadError] =
  mkVerifyLeaderProof(proof, public)

addOutputFormatter(new TimingCollector)
