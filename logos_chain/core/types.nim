# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Bedrock block types aligned with Nomos block construction / validation / execution.
## Spec: [Block Construction, Validation and Execution v1.3.0](https://github.com/logos-co/logos-lips/blob/4deef612ce1ae1776167daf8779d4abae953201b/docs/blockchain/raw/bedrock-v1.1-block-construction.md)

{.push raises: [], gcsafe.}

import
  std/sequtils,
  results,
  stew/[assign2, bitops2, endians2],
  bincode,
  bincode/types as bincodeTypes,
  libp2p/crypto/ed25519/ed25519,
  ./crypto/hashing,
  ./mantle/[tx_types, tx_hashing, tx_validation]

export
  hashing,
  tx_types,
  tx_hashing,
  results,
  bincodeTypes
export tx_validation except StatelessLedgerError

const
  MaxUncles* = 4
  HeaderSize* = 297
  SignedHeaderSize* = HeaderSize + EdSignatureSize

type
  ProofOfLeadershipProof = CompressedGroth16Proof

  ProofOfLeadership* = object
    # Declaration order IS the bincode wire order (the derive serializes
    # fields in order). The BLOCK_ID_V1 hash preimage uses a different,
    # spec-defined order — see `blockId`.
    proof*: ProofOfLeadershipProof
    entropyContribution*: ZkHash
    leaderKey*: Ed25519PublicKey
    leaderVoucher*: RewardVoucher

  BlockId* = Hash32
  
  Header* = object
    bedrockVersion*: uint8
    parentBlock*: BlockId
    slot*: SlotNumber
    bodyRoot*: Hash32
    proofOfLeadership*: ProofOfLeadership

  SignedHeader* = object
    header*: Header
    signature*: Ed25519Signature

  UncleHeaders* = BoundedSeq[SignedHeader, MaxUncles]
  BlockTxs* = BoundedSeq[HashedSignedMantleTx, MaxBlockTxs]
  References* = BoundedSeq[TxReference, MaxBlockTxs]

  Block* = object
    header*: Header
    signature*: Ed25519Signature
    uncleHeaders*: UncleHeaders
    txs*: BlockTxs

  # Encoded by `encodeProposal` / `decodeProposal` (Block Construction 1.3.0
  # "Canonical Encoding"), never by the bincode derive.
  Proposal* = object
    header*: Header
    uncleHeaders*: UncleHeaders
    references*: References
    signature*: Ed25519Signature

  ProposalDecodeError* {.pure.} = enum
    TruncatedInput
    TrailingBytes
    TooManyUncles      ## uncle count above `MaxUncles`
    TooManyReferences  ## reference count above `MaxBlockTxs`

const
  ExpectedBedrockVersion* = 1'u8
  GenesisBedrockVersion* = 1'u8
  MaxBlockSize* = 2_097_152
  DefaultHash32 = default(Hash32)
  DefaultBlockId* = default(BlockId)

deriveBincode(ProofOfLeadership)
deriveBincode(Header)
deriveBincode(SignedHeader)
deriveBincode(Block)

template header*(blk: Block): Header = blk.header

func hashPair*(left, right: Hash32): Hash32 =
  var pairBytes: array[64, byte]
  assign(pairBytes.toOpenArray(0, 31), left)
  assign(pairBytes.toOpenArray(32, 63), right)
  blake2b256Hash(pairBytes)

func encodeHeader*(header: Header): array[HeaderSize, byte] =
  ## Canonical 297-byte header encoding.
  # Wire order: version ‖ parent ‖ slot ‖ body root ‖ proof ‖ entropy ‖
  # leader key ‖ voucher. The block ID preimage uses another order.
  var res: array[HeaderSize, byte]
  res[0] = header.bedrockVersion
  assign(res.toOpenArray(1, 32), header.parentBlock)
  assign(res.toOpenArray(33, 40), encodeLe(header.slot))
  assign(res.toOpenArray(41, 72), header.bodyRoot)
  assign(res.toOpenArray(73, 200), header.proofOfLeadership.proof)
  assign(res.toOpenArray(201, 232), header.proofOfLeadership.entropyContribution)
  assign(res.toOpenArray(233, 264),
    encodeEd25519PublicKey(header.proofOfLeadership.leaderKey))
  assign(res.toOpenArray(265, 296), header.proofOfLeadership.leaderVoucher)
  res

func signHeader*(key: EdPrivateKey, header: Header): Ed25519Signature =
  ## Leader signature over the canonical header encoding.
  key.sign(encodeHeader(header))

func verify_signature*(header: Header, signature: Ed25519Signature): bool =
  ## True if `signature` is the leader signature over the canonical header
  ## encoding, under the leader key that the header commits to.
  signature.verifyStrict(encodeHeader(header), header.proofOfLeadership.leaderKey)

func encodeSignedHeader*(signed: SignedHeader): array[SignedHeaderSize, byte] =
  ## Canonical 361-byte signed header encoding.
  var res: array[SignedHeaderSize, byte]
  assign(res.toOpenArray(0, HeaderSize - 1), encodeHeader(signed.header))
  assign(res.toOpenArray(HeaderSize, SignedHeaderSize - 1),
    encodeEd25519Signature(signed.signature))
  res

func encodeProposal*(proposal: Proposal): seq[byte] =
  ## Canonical proposal encoding; the caller bounds both lists.
  doAssert proposal.uncleHeaders.len <= MaxUncles and
    proposal.references.len <= MaxBlockTxs
  let
    uncleCount = proposal.uncleHeaders.len
    referenceCount = proposal.references.len
    referenceCountOffset = HeaderSize + 1 + uncleCount * SignedHeaderSize
    signatureOffset =
      referenceCountOffset + 2 + referenceCount * ReferencePrefixLength
  # Every byte is written below, so the buffer needs no zero fill.
  var res = newSeqUninit[byte](signatureOffset + EdSignatureSize)
  assign(res.toOpenArray(0, HeaderSize - 1), encodeHeader(proposal.header))
  res[HeaderSize] = uint8(uncleCount)
  for i, uncle in proposal.uncleHeaders.asSeq:
    let start = HeaderSize + 1 + i * SignedHeaderSize
    assign(res.toOpenArray(start, start + SignedHeaderSize - 1),
      encodeSignedHeader(uncle))
  assign(res.toOpenArray(referenceCountOffset, referenceCountOffset + 1),
    encodeLe(uint16(referenceCount)))
  for i, reference in proposal.references.asSeq:
    let start = referenceCountOffset + 2 + i * ReferencePrefixLength
    assign(res.toOpenArray(start, start + ReferencePrefixLength - 1), reference)
  assign(res.toOpenArray(signatureOffset, res.high),
    encodeEd25519Signature(proposal.signature))
  res

func decodeHeader(data: openArray[byte]): Header =
  # Inverse of `encodeHeader`; `decodeProposal` checks the length first.
  doAssert data.len == HeaderSize
  var res: Header
  res.bedrockVersion = data[0]
  assign(res.parentBlock, data.toOpenArray(1, 32))
  res.slot = uint64.fromBytesLE(data.toOpenArray(33, 40))
  assign(res.bodyRoot, data.toOpenArray(41, 72))
  assign(res.proofOfLeadership.proof, data.toOpenArray(73, 200))
  assign(res.proofOfLeadership.entropyContribution, data.toOpenArray(201, 232))
  assign(res.proofOfLeadership.leaderKey.data, data.toOpenArray(233, 264))
  assign(res.proofOfLeadership.leaderVoucher, data.toOpenArray(265, 296))
  res

func decodeSignature(data: openArray[byte]): Ed25519Signature =
  doAssert data.len == EdSignatureSize
  var res: Ed25519Signature
  assign(res.data, data)
  res

func decodeProposal*(data: openArray[byte]): Result[Proposal, ProposalDecodeError] =
  ## Exact-length canonical decode; both counts are checked before any
  ## allocation that depends on them.
  if data.len < HeaderSize + 1:
    return err(ProposalDecodeError.TruncatedInput)
  let uncleCount = int(data[HeaderSize])
  if uncleCount > MaxUncles:
    return err(ProposalDecodeError.TooManyUncles)

  let referenceCountOffset = HeaderSize + 1 + uncleCount * SignedHeaderSize
  if data.len < referenceCountOffset + 2:
    return err(ProposalDecodeError.TruncatedInput)
  let referenceCount = int(uint16.fromBytesLE(
    data.toOpenArray(referenceCountOffset, referenceCountOffset + 1)))
  if referenceCount > MaxBlockTxs:
    return err(ProposalDecodeError.TooManyReferences)

  let
    signatureOffset =
      referenceCountOffset + 2 + referenceCount * ReferencePrefixLength
    total = signatureOffset + EdSignatureSize
  if data.len < total:
    return err(ProposalDecodeError.TruncatedInput)
  if data.len > total:
    return err(ProposalDecodeError.TrailingBytes)

  var
    uncles = newSeq[SignedHeader](uncleCount)
    references = newSeq[TxReference](referenceCount)
  for i in 0 ..< uncleCount:
    let start = HeaderSize + 1 + i * SignedHeaderSize
    uncles[i].header = decodeHeader(data.toOpenArray(start, start + HeaderSize - 1))
    uncles[i].signature = decodeSignature(
      data.toOpenArray(start + HeaderSize, start + SignedHeaderSize - 1))
  for i in 0 ..< referenceCount:
    let start = referenceCountOffset + 2 + i * ReferencePrefixLength
    assign(references[i], data.toOpenArray(start, start + ReferencePrefixLength - 1))

  ok(Proposal(
    header: decodeHeader(data.toOpenArray(0, HeaderSize - 1)),
    uncleHeaders: UncleHeaders(uncles),
    references: References(references),
    signature: decodeSignature(data.toOpenArray(signatureOffset, total - 1))))

proc encode*(
    stream: OutputStreamHandle, value: Proposal, config: BincodeConfig = standard()
) {.raises: [IOError].} =
  ## Bincode bridge: a proposal is always its canonical bytes.
  stream.write(encodeProposal(value))

func decodeAt*(
    data: openArray[byte],
    tParam: typedesc[Proposal],
    config: BincodeConfig = standard(),
    start: int = 0,
): (Proposal, int) {.raises: [BincodeError].} =
  ## Bincode bridge: canonical decode of the whole remaining input.
  if start < 0 or start > data.len:
    raise newException(BincodeError, "Invalid start offset for proposal")
  let proposal = decodeProposal(data.toOpenArray(start, data.high)).valueOr:
    raise newException(BincodeError, "proposal: " & $error)
  (proposal, data.len - start)

func merkle_root*(hashes: openArray[Hash32]): Hash32 =
  ## Merkle root over the transaction hashes in block order.
  ## Spec: [Cryptarchia Protocol v1.2.4, Block Header Validation](https://github.com/logos-co/logos-lips/blob/4deef612ce1ae1776167daf8779d4abae953201b/docs/blockchain/raw/cryptarchia-v1-protocol.md#block-header-validation)
  # Leaves pad with zero hashes to the next power of two, not with a copy of
  # the last leaf; the empty list is the zero hash (step 4).
  doAssert hashes.len <= MaxBlockTxs,
    "hash set exceeds MaxBlockTxs (" & $MaxBlockTxs & "): " & $hashes.len

  if hashes.len == 0:
    return DefaultHash32
  if hashes.len == 1:
    return hashes[0]

  let paddedLen = nextPow2(hashes.len.uint64).int
  var level = newSeq[Hash32](paddedLen)
  copyMem(addr level[0], unsafeAddr hashes[0], hashes.len * sizeof(Hash32))

  var curLen = paddedLen
  while curLen > 1:
    let parentLen = curLen div 2
    for i in 0 ..< parentLen:
      level[i] = hashPair(level[2 * i], level[2 * i + 1])
    curLen = parentLen

  level[0]

func body_root*(uncles: openArray[SignedHeader], txRoot: Hash32): Hash32 =
  ## blake2b256("BODY_ROOT_V1" ‖ u8 uncle count ‖ 361-byte entries ‖ merkle root).
  ## Spec: [Cryptarchia Protocol v1.2.4, Block Header Validation](https://github.com/logos-co/logos-lips/blob/4deef612ce1ae1776167daf8779d4abae953201b/docs/blockchain/raw/cryptarchia-v1-protocol.md#block-header-validation)
  # Every input path bounds the count first (`validateBlockStructure`,
  # `initHeader`, `initProposal`, the `BoundedSeq` decoder). A longer list
  # here is a programming error, not input.
  doAssert uncles.len <= MaxUncles,
    "uncle count exceeds MaxUncles (" & $MaxUncles & "): " & $uncles.len
  var preimage = newSeqOfCap[byte](
    1 + uncles.len * SignedHeaderSize + sizeof(Hash32))
  preimage.add(uint8(uncles.len))
  for uncle in uncles:
    preimage.add(encodeSignedHeader(uncle))
  preimage.add(txRoot)
  blake2b256Hash("BODY_ROOT_V1", preimage)

func body_root*(uncles: openArray[SignedHeader], txHashes: openArray[Hash32]): Hash32 =
  ## Body root over the uncle list and the transaction hashes.
  body_root(uncles, merkle_root(txHashes))

func body_root*[T: AnyHashedSignedMantleTx](
    uncles: openArray[SignedHeader],
    txs: openArray[T],
): Hash32 =
  ## Body root over the uncle list and precalculated hashes of transactions.
  body_root(uncles, merkle_root(txs.mapIt(it.hash)))

func blockId*(header: Header): Hash32 =
  ## block_id(header) = hash(
  ##   b"BLOCK_ID_V1",
  ##   header.bedrock_version,
  ##   header.parent_block,
  ##   header.slot.to_bytes(8, byteorder="little"),
  ##   header.body_root,
  ##   header.proof_of_leadership.leader_voucher,
  ##   header.proof_of_leadership.entropy_contribution,
  ##   header.proof_of_leadership.proof.serialize(),
  ##   header.proof_of_leadership.leader_key.compressed(),
  ## )
  const
    DomainTag = "BLOCK_ID_V1"
    PreimageCap = DomainTag.len + sizeof(header.bedrockVersion) +
      sizeof(header.parentBlock) + sizeof(uint64) + sizeof(header.bodyRoot) +
      sizeof(header.proofOfLeadership.leaderVoucher) +
      sizeof(header.proofOfLeadership.entropyContribution) +
      sizeof(header.proofOfLeadership.proof) + EdPublicKeySize

  var preimage = newSeqOfCap[byte](PreimageCap)
  preimage.add(DomainTag.toOpenArrayByte(0, DomainTag.high))
  preimage.add(header.bedrockVersion)
  preimage.add(header.parentBlock)
  preimage.add(encodeLe(header.slot))
  preimage.add(header.bodyRoot)
  preimage.add(header.proofOfLeadership.leaderVoucher)
  preimage.add(header.proofOfLeadership.entropyContribution)
  ## Proof is kept in serialized wire representation.
  preimage.add(header.proofOfLeadership.proof)

  ## Leader key compressed form.
  var leaderKeyBytes: array[EdPublicKeySize, byte]
  let written = toBytes(header.proofOfLeadership.leaderKey, leaderKeyBytes)
  doAssert written == EdPublicKeySize, "failed to encode proposal leader key"
  preimage.add(leaderKeyBytes)

  blake2b256Hash(preimage)

func initHeader*(
    bedrockVersion: uint8,
    parentBlock: BlockId,
    slot: SlotNumber,
    uncleHeaders: openArray[SignedHeader],
    txHashes: openArray[Hash32],
    proofOfLeadership: ProofOfLeadership,
): Header =
  ## Canonical constructor over transaction hashes; used for proposal construction.
  doAssert uncleHeaders.len <= MaxUncles,
    "uncle count exceeds MaxUncles (" & $MaxUncles & "): " & $uncleHeaders.len
  doAssert txHashes.len <= MaxBlockTxs,
    "block tx count exceeds MaxBlockTxs (" & $MaxBlockTxs & "): " & $txHashes.len
  Header(
    bedrockVersion: bedrockVersion,
    parentBlock: parentBlock,
    slot: slot,
    bodyRoot: body_root(uncleHeaders, txHashes),
    proofOfLeadership: proofOfLeadership,
  )

func initHeader*[T: AnyHashedSignedMantleTx](
    bedrockVersion: uint8,
    parentBlock: BlockId,
    slot: SlotNumber,
    uncleHeaders: openArray[SignedHeader],
    txs: openArray[T],
    proofOfLeadership: ProofOfLeadership,
): Header =
  ## Canonical constructor over verified transactions.
  doAssert uncleHeaders.len <= MaxUncles,
    "uncle count exceeds MaxUncles (" & $MaxUncles & "): " & $uncleHeaders.len
  doAssert txs.len <= MaxBlockTxs,
    "block tx count exceeds MaxBlockTxs (" & $MaxBlockTxs & "): " & $txs.len
  Header(
    bedrockVersion: bedrockVersion,
    parentBlock: parentBlock,
    slot: slot,
    bodyRoot: body_root(uncleHeaders, txs),
    proofOfLeadership: proofOfLeadership,
  )

func createGenesisHeader*(validGenesisTx: ValidGenesisMantleTx): Header =
  ## Genesis header: zero parent, slot 0, no uncles, default proof of leadership.
  initHeader(
    bedrockVersion = GenesisBedrockVersion,
    parentBlock = DefaultBlockId,
    slot = 0'u64,
    uncleHeaders = [],
    txs = [validGenesisTx],
    proofOfLeadership = ProofOfLeadership(
      leaderVoucher: default(RewardVoucher),
      entropyContribution: default(ZkHash),
      proof: DefaultCompressedGroth16Proof,
      leaderKey: DefaultEd25519PublicKey,
    ),
  )

func initProposal*(
    header: Header,
    uncleHeaders: openArray[SignedHeader],
    references: openArray[TxReference],
    signature: Ed25519Signature,
): Proposal =
  ## Canonical constructor; bounds the uncle count.
  doAssert uncleHeaders.len <= MaxUncles,
    "uncle count exceeds MaxUncles (" & $MaxUncles & "): " & $uncleHeaders.len
  doAssert references.len <= MaxBlockTxs,
    "reference count exceeds MaxBlockTxs (" & $MaxBlockTxs & "): " & $references.len
  Proposal(
    header: header, uncleHeaders: UncleHeaders(@uncleHeaders),
    references: References(@references), signature: signature)

{.pop.}
