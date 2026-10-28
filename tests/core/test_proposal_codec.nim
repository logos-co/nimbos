# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[algorithm, sequtils],
  stew/byteutils,
  unittest2,
  bincode,
  ../../logos_chain/core/types

const
  # Proposal over `fixtureHeader(0x00)`, three uncles, three references and
  # signature `[0x01; 64]`: 1,495 bytes. External vector, not made by this
  # encoder, in the layout of Block Construction 1.3.0, Canonical Encoding:
  # https://github.com/logos-co/logos-lips/blob/5fa8ee40c1de478b0934d95ddade7ce6a406fd1c/docs/blockchain/raw/bedrock-v1.1-block-construction.md#canonical-encoding
  # Replace it only when that section changes.
  ProposalHex =
    "0100000000000000000000000000000000000000000000000000000000000000002a000000000000" &
    "00222222222222222222222222222222222222222222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222222222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222222222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222222222222222222222222222222222222222222222" &
    "22555500000000000000000000000000000000000000000000000000000000000033333333333333" &
    "33333333333333333333333333333333333333333333333333444400000000000000000000000000" &
    "00000000000000000000000000000000000301666666666666666666666666666666666666666666" &
    "66666666666666666666662a00000000000000222222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222222222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222222222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222222222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222555500000000000000000000000000000000000000" &
    "00000000000000000000003333333333333333333333333333333333333333333333333333333333" &
    "33333344440000000000000000000000000000000000000000000000000000000000006666666666" &
    "66666666666666666666666666666666666666666666666666666666666666666666666666666666" &
    "66666666666666666666666666666666666666017777777777777777777777777777777777777777" &
    "7777777777777777777777772a000000000000002222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222222222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222222222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222222222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222225555000000000000000000000000000000000000" &
    "00000000000000000000000033333333333333333333333333333333333333333333333333333333" &
    "33333333444400000000000000000000000000000000000000000000000000000000000077777777" &
    "77777777777777777777777777777777777777777777777777777777777777777777777777777777" &
    "77777777777777777777777777777777777777770188888888888888888888888888888888888888" &
    "888888888888888888888888882a0000000000000022222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222222222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222222222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222222222222222222222222222222222222222222222" &
    "22222222222222222222222222222222222222222255550000000000000000000000000000000000" &
    "00000000000000000000000000333333333333333333333333333333333333333333333333333333" &
    "33333333334444000000000000000000000000000000000000000000000000000000000000888888" &
    "88888888888888888888888888888888888888888888888888888888888888888888888888888888" &
    "88888888888888888888888888888888888888888803000101010101010101010101010101010102" &
    "02020202020202020202020202020203030303030303030303030303030303010101010101010101" &
    "01010101010101010101010101010101010101010101010101010101010101010101010101010101" &
    "010101010101010101010101010101"

func fixtureHeader(id: byte): Header =
  var res = Header(bedrockVersion: 1'u8, slot: 42'u64)
  res.parentBlock.fill(id)
  res.bodyRoot.fill(0x22'u8)
  res.proofOfLeadership.proof.fill(0x22'u8)
  res.proofOfLeadership.entropyContribution[0] = 0x55'u8
  res.proofOfLeadership.entropyContribution[1] = 0x55'u8
  res.proofOfLeadership.leaderKey.data.fill(0x33'u8)
  res.proofOfLeadership.leaderVoucher[0] = 0x44'u8
  res.proofOfLeadership.leaderVoucher[1] = 0x44'u8
  res

func fixtureUncle(id: byte): SignedHeader =
  var res = SignedHeader(header: fixtureHeader(id))
  res.signature.data.fill(id)
  res

func fixtureReference(id: byte): TxReference =
  var res: TxReference
  res.fill(id)
  res

func fixtureProposal(): Proposal =
  var res = Proposal(
    header: fixtureHeader(0x00'u8),
    uncleHeaders: UncleHeaders(
      @[fixtureUncle(0x66'u8), fixtureUncle(0x77'u8), fixtureUncle(0x88'u8)]),
    references: References(
      @[fixtureReference(0x01'u8), fixtureReference(0x02'u8),
        fixtureReference(0x03'u8)]))
  res.signature.data.fill(0x01'u8)
  res

func sized(uncles, references: int): Proposal =
  Proposal(
    header: fixtureHeader(0x00'u8),
    uncleHeaders: UncleHeaders(newSeqWith(uncles, fixtureUncle(0x66'u8))),
    references: References(newSeqWith(references, fixtureReference(0x01'u8))))

suite "core/proposal codec":
  test "full proposal vector encodes and decodes, through the bincode bridge":
    # Guard: a layout, width or field-order error, or a bridge that still uses a bincode derive.
    let
      proposal = fixtureProposal()
      wire = hexToSeqByte(ProposalHex)
    check encodeProposal(proposal) == wire
    check decodeProposal(wire).get() == proposal
    try:
      check Bincode.encode(proposal, standard()) == wire
      check Bincode.decode(wire, Proposal, standard()) == proposal
    except SerializationError as exc:
      checkpoint exc.msg
      fail()
    expect SerializationError:
      discard Bincode.decode(wire & @[0'u8], Proposal, standard())

  test "decoding consumes the input exactly":
    # Guard: spec rule 4; a missing length check gives an IndexDefect, not an error.
    let wire = hexToSeqByte(ProposalHex)
    check decodeProposal(wire & @[0'u8]).error == ProposalDecodeError.TrailingBytes
    check decodeProposal(wire.toOpenArray(0, wire.len - 2)).error ==
      ProposalDecodeError.TruncatedInput
    check decodeProposal(wire.toOpenArray(0, HeaderSize + 100)).error ==
      ProposalDecodeError.TruncatedInput
    check decodeProposal(wire.toOpenArray(0, HeaderSize - 1)).error ==
      ProposalDecodeError.TruncatedInput

  test "counts at the bound decode, counts above it are rejected before any further read":
    # Guard: an off-by-one on either bound, or a bound check after the length check.
    let
      largest = sized(MaxUncles, MaxBlockTxs)
      largestWire = encodeProposal(largest)
    check largestWire.len == 18_192
    check decodeProposal(largestWire).get() == largest
    check encodeProposal(sized(0, 0)).len == 364

    var
      tooManyUncles = newSeq[byte](HeaderSize + 1)
      tooManyReferences = newSeq[byte](HeaderSize + 3)
    tooManyUncles[HeaderSize] = 5'u8
    tooManyReferences[HeaderSize + 1] = 0x01'u8 # 1025 = 0x0401, little-endian
    tooManyReferences[HeaderSize + 2] = 0x04'u8
    check decodeProposal(tooManyUncles).error == ProposalDecodeError.TooManyUncles
    check decodeProposal(tooManyReferences).error ==
      ProposalDecodeError.TooManyReferences

{.pop.}
