# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Genesis block construction from a signed genesis mantle transaction.
## Spec: [Bedrock Genesis Block v1.1.2](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-genesis-block.md)

{.push raises: [], gcsafe.}

import
  results,
  stew/endians2,
  ../core/types,
  ../core/crypto/hashing

from stew/byteutils import fromBytes

from ../core/crypto/types as crypto_types import encodeEd25519PublicKey
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

  # https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/bedrock-genesis-block.md#cryptarchia-parameters
  CryptarchiaParameter* = object
    ## Consensus parameters inscribed into the genesis block.
    chainId*: string
    genesisTime*: WallclockSeconds ## u32 on the wire
    epochNonce*: FieldElement

func decodeCryptarchiaParameter(
    inscribe: ChannelInscribePayload): Result[CryptarchiaParameter, cstring] =
  # Envelope checks (root parent, zero signer), then the payload.
  # Layout: u8 chain-id length ‖ utf8 chain id (1-255 bytes) ‖ u32-le unix
  # seconds ‖ 32-byte little-endian epoch nonce below the BN254 order.
  if inscribe.parent != static(default(Parent)):
    return err(cstring"genesis inscription parent is not the root message")
  if encodeEd25519PublicKey(inscribe.signer) != default(array[32, byte]):
    return err(cstring"genesis inscription signer is not zero")
  let data = inscribe.inscription
  if data.len < 1 + 1 + 4 + 32:
    return err(cstring"inscription too short")
  # A matching length implies a non-empty chain id (the minimum above
  # reserves one byte for it).
  let chainIdLen = int(data[0])
  if chainIdLen != data.len - 1 - 4 - 32:
    return err(cstring"inscription length mismatch")
  let
    timeStart = 1 + chainIdLen
    nonce = frFromBytesLE(data.toOpenArray(timeStart + 4, timeStart + 35)).valueOr:
      return err(cstring"epoch nonce exceeds the BN254 order")
  ok(CryptarchiaParameter(
    chainId: string.fromBytes(data.toOpenArray(1, timeStart - 1)),
    genesisTime: WallclockSeconds(
      uint32.fromBytesLE(data.toOpenArray(timeStart, timeStart + 3))),
    epochNonce: nonce))

func cryptarchiaParameter*(
    state: GenesisState): Result[CryptarchiaParameter, cstring] =
  ## Decode the Cryptarchia parameters from the genesis tx's null-channel
  ## inscription (root parent, zero signer).
  for op in state.signedMantleTx.tx.ops:
    if op.payload.kind == OpPayloadTag.ChannelInscribe and
        op.payload.channelInscribe.channelId == static(default(ChannelId)):
      return decodeCryptarchiaParameter(op.payload.channelInscribe)
  err(cstring"genesis tx has no null-channel inscription")

func createGenesisHeader(genesisMantleTx: SignedMantleTx): Header =
  ## Genesis header constructor using spec defaults:
  ## - parent block id = zero hash
  ## - slot = 0
  ## - proof-of-leadership fields = zero/default
  initHeader(
    bedrockVersion = GenesisBedrockVersion,
    parentBlock = default(BlockId),
    slot = 0'u64,
    txs = [genesisMantleTx],
    proofOfLeadership = ProofOfLeadership(
      leaderVoucher: default(RewardVoucher),
      entropyContribution: default(ZkHash),
      proof: DefaultCompressedGroth16Proof,
      leaderKey: default(Ed25519PublicKey),
    ),
  )

func createGenesisBlock*(genesisMantleTx: SignedMantleTx): Block =
  ## GENESIS_BLOCK = (GENESIS_HEADER, GENESIS_SIGNATURE, [GENESIS_MANTLE_TX])
  let genesisHeader = createGenesisHeader(genesisMantleTx)
  initBlock(genesisHeader, DefaultEd25519Signature, [genesisMantleTx])

{.pop.}
