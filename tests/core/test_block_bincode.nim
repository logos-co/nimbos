# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/sequtils,
  results,
  stew/[byteutils, endians2],
  unittest2,
  ../testutil,
  bincode,
  ../../logos_chain/core/types,
  ../../logos_chain/chain/block_validation,
  ../../logos_chain/sync/types

from libp2p/crypto/ed25519/ed25519 import EdSignatureSize

const cfg = cryptarchiaSyncBincodeConfig

func sampleHeader(
    txs: openArray[HashedSignedMantleTx], uncles: openArray[SignedHeader] = []): Header =
  initHeader(
    bedrockVersion = ExpectedBedrockVersion,
    parentBlock = default(BlockId),
    slot = 1'u64,
    uncleHeaders = uncles,
    txs = txs,
    proofOfLeadership = ProofOfLeadership(
      leaderVoucher: default(RewardVoucher),
      entropyContribution: default(ZkHash),
      proof: DefaultCompressedGroth16Proof,
      leaderKey: default(Ed25519PublicKey),
    ),
  )

proc checkBlockEqual(a, b: Block) =
  check a.header == b.header
  check a.signature == b.signature
  check a.uncleHeaders == b.uncleHeaders
  check a.txs.len == b.txs.len
  for i in 0 ..< a.txs.len:
    check a.txs[i].hash == b.txs[i].hash
    check encodeSignedMantleTx(a.txs[i]) == encodeSignedMantleTx(b.txs[i])

template roundtrip(blk: Block): untyped =
  decode(encode(blk, cfg), Block, cfg)

suite "core/block bincode (cryptarchia sync)":
  test "encode / decode roundtrip (default signature, empty txs)":
    let blk = initBlock(sampleHeader([]), uncleHeaders = [], txs = [])
    try:
      checkBlockEqual(roundtrip(blk), blk)
    except BincodeError:
      fail getCurrentExceptionMsg()

  test "encode / decode roundtrip (non-default signature, one tx)":
    var sig: Ed25519Signature
    for i in 0 ..< EdSignatureSize:
      sig.data[i] = byte(i)
    let
      sm = minimalHashedSignedTx()
      blk = initBlock(sampleHeader([sm]), signature = sig, uncleHeaders = [], txs = [sm])
    try:
      let back = roundtrip(blk)
      checkBlockEqual(back, blk)
      check back.signature.data[0] == 0'u8
      check back.signature.data[EdSignatureSize - 1] == byte(EdSignatureSize - 1)
    except BincodeError:
      fail getCurrentExceptionMsg()

  test "encode / decode roundtrip (genesis block)":
    let genesis = initGenesisBlock(testValidGenesisTx())
    try:
      checkBlockEqual(roundtrip(genesis), genesis)
      check genesis.signature == DefaultEd25519Signature
    except BincodeError:
      fail getCurrentExceptionMsg()

  test "encode(ValidBlock) matches encode(Block) exactly":
    let
      validGenesis = testGenesisBlock()
      blockGenesis = initGenesisBlock(testValidGenesisTx())
    try:
      let
        vWire = encode(validGenesis, cfg)
        bWire = encode(blockGenesis, cfg)
      check vWire == bWire
      let decoded = decode(vWire, Block, cfg)
      checkBlockEqual(decoded, blockGenesis)
    except BincodeError:
      fail getCurrentExceptionMsg()

  test "bincode field order is header, signature, uncles, txs":
    let
      sm = minimalHashedSignedTx()
      h = sampleHeader([sm])
    var sig: Ed25519Signature
    sig.data[0] = 0xAA'u8
    sig.data[1] = 0xBB'u8
    let blk = initBlock(h, signature = sig, uncleHeaders = [], txs = [sm])
    try:
      let
        hdrWire = encode(h, cfg)
        blkWire = encode(blk, cfg)
      check blkWire.len > hdrWire.len + EdSignatureSize
      check blkWire[hdrWire.len] == 0xAA'u8
      check blkWire[hdrWire.len + 1] == 0xBB'u8
      let uncleLenOff = hdrWire.len + EdSignatureSize
      check blkWire[uncleLenOff] == 0'u8
      let txsLenOff = uncleLenOff + 8
      check blkWire[txsLenOff] == 1'u8
      check blkWire[txsLenOff + 1] == 0'u8
    except BincodeError:
      fail getCurrentExceptionMsg()

  test "serialized block wire includes signature bytes in payload size":
    let
      sm = minimalHashedSignedTx()
      h = sampleHeader([sm])
    try:
      let withDefaultSig = encode(initBlock(h, uncleHeaders = [], txs = [sm]), cfg)
      var sig: Ed25519Signature
      sig.data[0] = 0x55'u8
      let withMarkedSig = encode(initBlock(h, signature = sig, uncleHeaders = [], txs = [sm]), cfg)
      check withDefaultSig.len == withMarkedSig.len
      check withDefaultSig != withMarkedSig
      check withMarkedSig.len > EdSignatureSize
    except BincodeError:
      fail getCurrentExceptionMsg()

  test "encode / decode roundtrip (Proposal)":
    let
      sm = minimalHashedSignedTx()
      h = sampleHeader([sm])
    var proposal = new(Proposal)
    proposal.header = h
    proposal.references[0] = sm.hash
    proposal.signature = DefaultEd25519Signature
    try:
      let serialized = encode(proposal[], cfg)
      check sizeof(proposal.references) == 32768
      check serialized.len == 33137
      var deserialized = new(Proposal)
      deserialized[] = decode(serialized, Proposal, cfg)
      check deserialized.header == proposal.header
      check deserialized.uncleHeaders.len == 0
      check deserialized.references == proposal.references
      check deserialized.signature == proposal.signature
    except BincodeError:
      fail getCurrentExceptionMsg()

  test "empty block encodes to 377 bytes":
    let blk = initBlock(sampleHeader([]), uncleHeaders = [], txs = [])
    try:
      check encode(blk, cfg).len == 377
    except BincodeError:
      fail getCurrentExceptionMsg()

  test "encode / decode roundtrip (two uncles, one tx)":
    var sig: Ed25519Signature
    sig.data[0] = 0x0F'u8
    let
      sm = minimalHashedSignedTx()
      uncles = [
        SignedHeader(header: sampleHeader([]), signature: sig),
        SignedHeader(header: sampleHeader([sm]), signature: DefaultEd25519Signature),
      ]
      blk = initBlock(
        sampleHeader([sm], uncles), signature = sig, uncleHeaders = uncles,
        txs = [sm])
    try:
      let back = roundtrip(blk)
      checkBlockEqual(back, blk)
      check back.uncleHeaders.len == 2
      # Each transaction carries a u64 byte-length prefix on the sync wire.
      check encode(blk, cfg).len ==
        377 + 2 * SignedHeaderSize + 8 + encodeSignedMantleTx(sm).get.len
    except BincodeError:
      fail getCurrentExceptionMsg()

  test "decode rejects more than MaxUncles uncles (Block and Proposal)":
    let
      uncle = SignedHeader(
        header: sampleHeader([]), signature: DefaultEd25519Signature)
      tooMany = UncleHeaders(newSeqWith(MaxUncles + 1, uncle))
      atLimit = UncleHeaders(newSeqWith(MaxUncles, uncle))
      h = sampleHeader([])
    var
      proposal = new(Proposal)
      wireBlock, wireProposal: seq[byte]
    proposal.header = h
    try:
      # Not `initBlock`: the constructor asserts the bound.
      check decode(
        encode(Block(header: h, uncleHeaders: atLimit), cfg), Block, cfg
      ).uncleHeaders.len == MaxUncles
      wireBlock = encode(Block(header: h, uncleHeaders: tooMany), cfg)
      proposal.uncleHeaders = tooMany
      wireProposal = encode(proposal[], cfg)
    except BincodeError:
      fail getCurrentExceptionMsg()
    expect BincodeError:
      discard decode(wireBlock, Block, cfg)
    expect BincodeError:
      var decoded = new(Proposal)
      decoded[] = decode(wireProposal, Proposal, cfg)

  test "decode rejects a false uncle count with no uncle data":
    # The uncle count follows the header. A large count with no elements
    # must fail before the decoder allocates for it.
    let h = sampleHeader([])
    var wire: seq[byte]
    try:
      wire = encode(h, cfg)
    except BincodeError:
      fail getCurrentExceptionMsg()
    wire.add toBytesLE(10_000_000'u64)
    expect BincodeError:
      var decoded = new(Proposal)
      decoded[] = decode(wire, Proposal, cfg)

  test "decode rejects more than MaxBlockTxs transactions":
    let
      sm = minimalHashedSignedTx()
      h = sampleHeader([])
    var atLimit, tooMany: seq[byte]
    try:
      atLimit = encode(
        Block(header: h, txs: BlockTxs(newSeqWith(MaxBlockTxs, sm))), cfg)
      tooMany = encode(
        Block(header: h, txs: BlockTxs(newSeqWith(MaxBlockTxs + 1, sm))), cfg)
      check decode(atLimit, Block, cfg).txs.len == MaxBlockTxs
    except BincodeError:
      fail getCurrentExceptionMsg()
    expect BincodeError:
      discard decode(tooMany, Block, cfg)

  test "block golden wire bytes parity (multiple tx kinds and uncles)":
    const GoldenBlockHex =
      "01000000000000000000000000000000000000000000000000000000000000000064000000000000007e6f4d7d41234d58b1a0f470ef3ae89ce47b393091f93cc390781eb24fb3017b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4001000000000000000100000000000000000000000000000000000000000000000000000000000000002a00000000000000273a6e9869625d85c45e53afff1d3100aec613d403be494c173030e6a05e4c9c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000403f3e3d3c3b3a393837363534333231302f2e2d2c2b2a292827262524232221201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010300000000000000010000000000000000880100000000000002000001f401000000000000010000000000000000000000000000000000000000000000000000000000000011000000000000000000000000000000000000000000000000000000000000000037000000126e696d626f732d676f6c64656e2d7465737400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ac0000000000000001000001393000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

    var sig: Ed25519Signature
    for i in 0 ..< 64:
      sig.data[i] = byte(i + 1)

    var uncleSig: Ed25519Signature
    for i in 0 ..< 64:
      uncleSig.data[i] = byte(64 - i)

    let uncleHeader = initHeader(
      bedrockVersion = ExpectedBedrockVersion,
      parentBlock = default(BlockId),
      slot = 42'u64,
      uncleHeaders = [],
      txHashes = [default(Hash32)],
      proofOfLeadership = ProofOfLeadership(
        leaderVoucher: default(RewardVoucher),
        entropyContribution: default(ZkHash),
        proof: DefaultCompressedGroth16Proof,
        leaderKey: default(Ed25519PublicKey),
      ),
    )
    let uncle = SignedHeader(header: uncleHeader, signature: uncleSig)

    let
      tx1 = minimalHashedSignedTx()
      tx2 = testGenesisHtx(outputs = [Note(value: 500, zkPublicKey: testZkPk())], chainId = "nimbos-golden-test")
      tx3 = createGenesisHtx(txWithPlaceholderProofs([
        createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[Note(value: 12345, zkPublicKey: testZkPk())])
        ))
      ])).get

    let blkHeader = initHeader(
      bedrockVersion = ExpectedBedrockVersion,
      parentBlock = default(BlockId),
      slot = 100'u64,
      uncleHeaders = [uncle],
      txs = [tx1, tx2, tx3],
      proofOfLeadership = ProofOfLeadership(
        leaderVoucher: default(RewardVoucher),
        entropyContribution: default(ZkHash),
        proof: DefaultCompressedGroth16Proof,
        leaderKey: default(Ed25519PublicKey),
      ),
    )

    let blk = Block(
      header: blkHeader,
      signature: sig,
      uncleHeaders: UncleHeaders(@[uncle]),
      txs: BlockTxs(@[tx1, tx2, tx3]),
    )

    let goldenBytes = hexToSeqByte(GoldenBlockHex)
    check encode(blk, cfg) == goldenBytes
    checkBlockEqual(roundtrip(blk), blk)
    let decoded = decode(goldenBytes, Block, cfg)
    checkBlockEqual(decoded, blk)
    check encode(decoded, cfg) == goldenBytes

{.pop.}
