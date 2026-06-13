# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  ../testutil,
  bincode,
  ../../logos_chain/core/[types, mantle/tx_types],
  ../../logos_chain/chain/genesis,
  ../../logos_chain/sync/types

from libp2p/crypto/ed25519/ed25519 import EdSignatureSize

const cfg = cryptarchiaSyncBincodeConfig

func sampleHeader(txs: openArray[SignedMantleTx]): Header =
  initHeader(
    bedrockVersion = ExpectedBedrockVersion,
    parentBlock = default(BlockId),
    slot = 1'u64,
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
  check a.txs.len == b.txs.len
  for i in 0 ..< a.txs.len:
    check encodeSignedMantleTx(a.txs[i]) == encodeSignedMantleTx(b.txs[i])

template roundtrip(blk: Block): untyped =
  deserializeBlock(serializeBlockToSeq(blk, cfg), cfg)

suite "core/block bincode (cryptarchia sync)":
  test "serializeBlockToSeq / deserializeBlock roundtrip (default signature, empty txs)":
    let blk = initBlock(sampleHeader([]), txs = [])
    try:
      checkBlockEqual(roundtrip(blk), blk)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()

  test "serializeBlockToSeq / deserializeBlock roundtrip (non-default signature, one tx)":
    var sig = default(Ed25519Signature)
    for i in 0 ..< EdSignatureSize:
      sig.data[i] = byte(i)
    let
      sm = minimalSignedTx()
      blk = initBlock(sampleHeader([sm]), signature = sig, txs = [sm])
    try:
      let back = roundtrip(blk)
      checkBlockEqual(back, blk)
      check back.signature.data[0] == 0'u8
      check back.signature.data[EdSignatureSize - 1] == byte(EdSignatureSize - 1)
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()

  test "serializeBlockToSeq / deserializeBlock roundtrip (genesis block)":
    let genesis = createGenesisBlock(minimalSignedTx())
    try:
      checkBlockEqual(roundtrip(genesis), genesis)
      check genesis.signature == DefaultEd25519Signature
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()

  test "bincode field order is header then signature then txs":
    let
      sm = minimalSignedTx()
      h = sampleHeader([sm])
    var sig = default(Ed25519Signature)
    sig.data[0] = 0xAA'u8
    sig.data[1] = 0xBB'u8
    let blk = initBlock(h, signature = sig, txs = [sm])
    try:
      let
        hdrWire = serializeHeaderToSeq(h, cfg)
        blkWire = serializeBlockToSeq(blk, cfg)
      check blkWire.len > hdrWire.len + EdSignatureSize
      check blkWire[hdrWire.len] == 0xAA'u8
      check blkWire[hdrWire.len + 1] == 0xBB'u8
      let txsLenOff = hdrWire.len + EdSignatureSize
      check blkWire[txsLenOff] == 1'u8
      check blkWire[txsLenOff + 1] == 0'u8
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()

  test "serialized block wire includes signature bytes in payload size":
    let
      sm = minimalSignedTx()
      h = sampleHeader([sm])
    try:
      let withDefaultSig = serializeBlockToSeq(initBlock(h, txs = [sm]), cfg)
      var sig = default(Ed25519Signature)
      sig.data[0] = 0x55'u8
      let withMarkedSig = serializeBlockToSeq(initBlock(h, signature = sig, txs = [sm]), cfg)
      check withDefaultSig.len == withMarkedSig.len
      check withDefaultSig != withMarkedSig
      check withMarkedSig.len > EdSignatureSize
      check withMarkedSig.len <= MaxBlockSize
    except BincodeError, IOError:
      fail getCurrentExceptionMsg()

{.pop.}
