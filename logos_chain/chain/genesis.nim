# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Genesis block construction from a signed genesis mantle transaction.
## Spec: [Bedrock Genesis Block v1.2.0](https://github.com/logos-co/logos-lips/blob/b7301a67b5364a8dbe719f8b67b96b7f198d0a13/docs/blockchain/raw/bedrock-genesis-block.md)
## The "Initial Proof of Work Reward Pool" section is not implemented.

{.push raises: [], gcsafe.}

import
  results,
  stew/endians2,
  ../core/types,
  ../core/crypto/hashing

from stew/byteutils import fromBytes

from ../core/utils import isUtf8
from ../core/crypto/types as crypto_types import DefaultEd25519PublicKey
from ../consensus/clock import WallclockSeconds

export results, types, hashing, WallclockSeconds

const
  GenesisBedrockVersion* = 1'u8

type
  GenesisState* = object
    signedMantleTx*: SignedMantleTx
    faucetZkPublicKey*: ZkPublicKey
    header*: Header
    blockSignature*: Ed25519Signature

  # https://github.com/logos-co/logos-lips/blob/b7301a67b5364a8dbe719f8b67b96b7f198d0a13/docs/blockchain/raw/bedrock-genesis-block.md#cryptarchia-parameters
  CryptarchiaParameter* = object
    ## Consensus parameters inscribed into the genesis block.
    chainId*: string
    genesisTime*: WallclockSeconds ## u32 on the wire
    epochNonce*: FieldElement

func decodeCryptarchiaParameter(
    data: openArray[byte]): Result[CryptarchiaParameter, cstring] =
  # Layout: u8 chain-id length ‖ utf8 chain id (1-255 bytes) ‖ u32-le unix
  # seconds ‖ 32-byte little-endian epoch nonce below the BN254 order.
  # The minimum reserves one byte for the chain id: an empty chain id names
  # no network.
  if data.len < 1 + 1 + 4 + 32:
    return err(cstring"inscription too short")
  # An exact length match rejects trailing bytes.
  let chainIdLen = int(data[0])
  if chainIdLen != data.len - 1 - 4 - 32:
    return err(cstring"inscription length mismatch")
  let timeStart = 1 + chainIdLen
  if not isUtf8(data.toOpenArray(1, timeStart - 1)):
    return err(cstring"chain id is not valid UTF-8")
  let nonce = frFromBytesLE(data.toOpenArray(timeStart + 4, timeStart + 35)).valueOr:
    return err(cstring"epoch nonce exceeds the BN254 order")
  ok(CryptarchiaParameter(
    chainId: string.fromBytes(data.toOpenArray(1, timeStart - 1)),
    genesisTime: WallclockSeconds(
      uint32.fromBytesLE(data.toOpenArray(timeStart, timeStart + 3))),
    epochNonce: nonce))

func cryptarchiaParameter*(
    tx: ValidGenesisMantleTx): Result[CryptarchiaParameter, cstring] =
  ## Decode the Cryptarchia parameters from the genesis inscription.
  decodeCryptarchiaParameter(tx.tx.ops[1].payload.channelInscribe.inscription)

func createGenesisHeader(genesisMantleTx: SignedMantleTx): Header =
  ## Genesis header constructor using spec defaults:
  ## - parent block id = zero hash
  ## - slot = 0
  ## - proof-of-leadership fields = zero/default
  initHeader(
    bedrockVersion = GenesisBedrockVersion,
    parentBlock = DefaultBlockId,
    slot = 0'u64,
    txs = [genesisMantleTx],
    proofOfLeadership = ProofOfLeadership(
      leaderVoucher: default(RewardVoucher),
      entropyContribution: default(ZkHash),
      proof: DefaultCompressedGroth16Proof,
      leaderKey: DefaultEd25519PublicKey,
    ),
  )

func createGenesisBlock*(genesisMantleTx: SignedMantleTx): Block =
  ## GENESIS_BLOCK = (GENESIS_HEADER, GENESIS_SIGNATURE, [GENESIS_MANTLE_TX])
  let genesisHeader = createGenesisHeader(genesisMantleTx)
  initBlock(genesisHeader, DefaultEd25519Signature, [genesisMantleTx])

{.pop.}
