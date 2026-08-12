# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Bedrock block types aligned with Nomos block construction / validation / execution.
## Spec: [Block Construction, Validation and Execution v1.1.2](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-block-construction.md)

{.push raises: [], gcsafe.}

import
  stew/[assign2, bitops2],
  bincode,
  ./crypto/hashing,
  ./mantle/[tx_types, tx_hashing, tx_bincode],
  libp2p/crypto/ed25519/ed25519

export hashing, tx_types, tx_bincode

const
  ExpectedBedrockVersion* = 1'u8
  MaxBlockSize* = 1_048_576

type
  ProofOfLeadershipProof* = CompressedGroth16Proof

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
    blockRoot*: Hash32
    proofOfLeadership*: ProofOfLeadership

  Block* = object
    header*: Header
    signature*: Ed25519Signature
    txs*: seq[SignedMantleTx]

  Proposal* = object
    header*: Header
    references*: References
    signature*: Ed25519Signature

deriveBincode(ProofOfLeadership)
deriveBincode(Header)
deriveBincode(Block)

template header*(blk: Block): auto = blk.header

func hashPair*(left, right: Hash32): Hash32 =
  var pairBytes: array[64, byte]
  assign(pairBytes.toOpenArray(0, 31), left)
  assign(pairBytes.toOpenArray(32, 63), right)
  blake2b256Hash(pairBytes)

func createBlockRoot*(txs: openArray[SignedMantleTx]): Hash32 =
  ## Computes Merkle root over tx hashes (in block order).
  ## Pads the leaf layer to the next power of two with zero ``Hash32`` leaves,
  ## then pairs ``left || right`` with BLAKE2b-256.
  ## Empty-root returns default(Hash32) zero hash per Bedrock Block Construction v1.1.2.
  doAssert txs.len <= MaxBlockTxs,
    "tx set exceeds MaxBlockTxs (" & $MaxBlockTxs & "): " & $txs.len

  if txs.len == 0:
    return default(Hash32)

  let paddedLen = nextPow2(txs.len.uint64).int
  var level = newSeq[Hash32](paddedLen)
  for i, stx in txs:
    level[i] = mantleTxHash(stx.tx)

  while level.len > 1:
    let parentLen = level.len div 2
    var parents = newSeq[Hash32](parentLen)
    for i in 0 ..< parentLen:
      parents[i] = hashPair(level[2 * i], level[2 * i + 1])
    level = parents

  level[0]

func blockId*(header: Header): Hash32 =
  ## block_id(header) = hash(
  ##   b"BLOCK_ID_V1",
  ##   header.bedrock_version,
  ##   header.parent_block,
  ##   header.slot.to_bytes(8, byteorder="little"),
  ##   header.block_root,
  ##   header.proof_of_leadership.leader_voucher,
  ##   header.proof_of_leadership.entropy_contribution,
  ##   header.proof_of_leadership.proof.serialize(),
  ##   header.proof_of_leadership.leader_key.compressed(),
  ## )
  var preimage: seq[byte]
  for c in "BLOCK_ID_V1":
    preimage.add(byte(ord(c)))

  preimage.add(header.bedrockVersion)
  preimage.add(header.parentBlock)
  preimage.add(encodeLe(header.slot))
  preimage.add(header.blockRoot)
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


func initBlock*(
    header: Header,
    signature: Ed25519Signature = DefaultEd25519Signature,
    txs: openArray[SignedMantleTx],
): Block =
  ## Canonical constructor that enforces block tx count limit.
  doAssert txs.len <= MaxBlockTxs,
    "block tx count exceeds MaxBlockTxs (" & $MaxBlockTxs & "): " & $txs.len
  Block(header: header, signature: signature, txs: @txs)

func initHeader*(
    bedrockVersion: uint8,
    parentBlock: BlockId,
    slot: SlotNumber,
    txs: openArray[SignedMantleTx],
    proofOfLeadership: ProofOfLeadership,
): Header =
  ## Canonical constructor for block headers.
  Header(
    bedrockVersion: bedrockVersion,
    parentBlock: parentBlock,
    slot: slot,
    blockRoot: createBlockRoot(txs),
    proofOfLeadership: proofOfLeadership,
  )

{.pop.}
