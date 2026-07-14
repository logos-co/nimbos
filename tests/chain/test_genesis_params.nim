# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  stew/byteutils,
  unittest2,
  libp2p/crypto/ed25519/ed25519,
  ../../logos_chain/chain/genesis

# Worked example per `bedrock-genesis-block.md` §Cryptarchia Parameters:
# chain id "nomos-mainnet", genesis time 2026-01-05T19:20:35+00:00 (u32-le),
# little-endian nonce below the BN254 order.
const
  SpecNonceHex =
    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567800"
  SpecInscription = hexToSeqByte(
    "0d6e6f6d6f732d6d61696e6e6574030f5c69" & SpecNonceHex)

func genesisStateWith(
    inscription: seq[byte],
    channelId: ChannelId,
    parent = default(Parent),
    signer = default(Signer),
): GenesisState =
  GenesisState(
    signedMantleTx: SignedMantleTx(
      tx: MantleTx(ops: @[
        Op(payload: OpPayload(
          kind: OpPayloadTag.ChannelInscribe,
          channelInscribe: ChannelInscribePayload(
            channelId: channelId,
            inscription: inscription,
            parent: parent,
            signer: signer)))])))

suite "chain/genesis cryptarchia parameters":
  test "decodes the spec worked example":
    let param = genesisStateWith(
      SpecInscription, default(ChannelId)
    ).cryptarchiaParameter.expect("valid inscription")
    check:
      param.chainId == "nomos-mainnet"
      param.genesisTime == 0x695c0f03'u64
      param.epochNonce ==
        frFromBytesLE(hexToSeqByte(SpecNonceHex)).expect("below order")

  test "rejects a truncated inscription":
    var bytes = SpecInscription
    bytes.setLen(bytes.len - 1)
    check genesisStateWith(bytes, default(ChannelId)).cryptarchiaParameter.isErr

  test "rejects a chain-id length that disagrees with the payload":
    var bytes = SpecInscription
    bytes[0] = 0x0c # claims 12 bytes; payload has 13
    check genesisStateWith(bytes, default(ChannelId)).cryptarchiaParameter.isErr

  test "rejects an epoch nonce at or above the BN254 order":
    var bytes = SpecInscription
    bytes[^1] = 0x90 # little-endian top byte 0x90 > the order's 0x30
    check genesisStateWith(bytes, default(ChannelId)).cryptarchiaParameter.isErr

  test "rejects an inscription whose parent is not the root message":
    var parent: Parent
    parent[0] = 1
    check genesisStateWith(
      SpecInscription, default(ChannelId), parent).cryptarchiaParameter.isErr

  test "rejects an inscription whose signer is not zero":
    var raw: array[32, byte]
    raw[0] = 1
    var signer: Signer
    check signer.init(raw)
    check genesisStateWith(
      SpecInscription, default(ChannelId), signer = signer
    ).cryptarchiaParameter.isErr

  test "ignores inscriptions on non-null channels":
    var channel: ChannelId
    channel[0] = 1
    check genesisStateWith(
      SpecInscription, channel).cryptarchiaParameter.isErr

  test "errors when the genesis tx has no inscription":
    check GenesisState().cryptarchiaParameter.isErr

{.pop.}
