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
  stew/endians2,
  bincode,
  ../../logos_chain/chain/genesis,
  ../../logos_chain/sync/types,
  ../testutil

from libp2p/crypto/ed25519/ed25519 import EdSignatureSize

const cfg = cryptarchiaSyncBincodeConfig

func sampleHeader(
    txs: openArray[SignedMantleTx], uncles: openArray[SignedHeader] = []): Header =
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
  ).get

proc checkBlockEqual(a, b: Block) =
  check:
    a.header == b.header
    a.signature == b.signature
    a.uncleHeaders == b.uncleHeaders
    a.txs.len == b.txs.len
  for i in 0 ..< a.txs.len:
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
      sm = minimalSignedTx()
      blk = initBlock(sampleHeader([sm]), signature = sig, uncleHeaders = [], txs = [sm])
    try:
      let back = roundtrip(blk)
      checkBlockEqual(back, blk)
      check:
        back.signature.data[0] == 0'u8
        back.signature.data[EdSignatureSize - 1] == byte(EdSignatureSize - 1)
    except BincodeError:
      fail getCurrentExceptionMsg()

  test "encode / decode roundtrip (genesis block)":
    let genesis = createGenesisBlock(minimalSignedTx()).get
    try:
      checkBlockEqual(roundtrip(genesis), genesis)
      check genesis.signature == DefaultEd25519Signature
    except BincodeError:
      fail getCurrentExceptionMsg()

  test "bincode field order is header, signature, uncles, txs":
    let
      sm = minimalSignedTx()
      h = sampleHeader([sm])
    var sig: Ed25519Signature
    sig.data[0] = 0xAA'u8
    sig.data[1] = 0xBB'u8
    let blk = initBlock(h, signature = sig, uncleHeaders = [], txs = [sm])
    try:
      let
        hdrWire = encode(h, cfg)
        blkWire = encode(blk, cfg)
      check:
        blkWire.len > hdrWire.len + EdSignatureSize
        blkWire[hdrWire.len] == 0xAA'u8
        blkWire[hdrWire.len + 1] == 0xBB'u8
      let uncleLenOff = hdrWire.len + EdSignatureSize
      check blkWire[uncleLenOff] == 0'u8
      let txsLenOff = uncleLenOff + 8
      check:
        blkWire[txsLenOff] == 1'u8
        blkWire[txsLenOff + 1] == 0'u8
    except BincodeError:
      fail getCurrentExceptionMsg()

  test "serialized block wire includes signature bytes in payload size":
    let
      sm = minimalSignedTx()
      h = sampleHeader([sm])
    try:
      let withDefaultSig = encode(initBlock(h, uncleHeaders = [], txs = [sm]), cfg)
      var sig: Ed25519Signature
      sig.data[0] = 0x55'u8
      let withMarkedSig = encode(initBlock(h, signature = sig, uncleHeaders = [], txs = [sm]), cfg)
      check:
        withDefaultSig.len == withMarkedSig.len
        withDefaultSig != withMarkedSig
        withMarkedSig.len > EdSignatureSize
    except BincodeError:
      fail getCurrentExceptionMsg()

  test "encode / decode roundtrip (Proposal)":
    let
      sm = minimalSignedTx()
      h = sampleHeader([sm])
    var proposal = new(Proposal)
    proposal.header = h
    proposal.references[0] = mantleTxHash(sm.tx).get
    proposal.signature = DefaultEd25519Signature
    try:
      let serialized = encode(proposal[], cfg)
      check:
        sizeof(proposal.references) == 32768
        serialized.len == 33137
      var deserialized = new(Proposal)
      deserialized[] = decode(serialized, Proposal, cfg)
      check:
        deserialized.header == proposal.header
        deserialized.uncleHeaders.len == 0
        deserialized.references == proposal.references
        deserialized.signature == proposal.signature
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
      sm = minimalSignedTx()
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
      sm = minimalSignedTx()
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

{.pop.}
