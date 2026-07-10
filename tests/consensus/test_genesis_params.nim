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
  ../../logos_chain/chain/genesis

# Worked example from `bedrock-genesis-block.md` §Cryptarchia Parameters:
# chain id "nomos-mainnet", genesis time 2026-01-05T19:20:35+00:00,
# nonce abcdef… repeated.
const SpecInscription = hexToSeqByte(
  "0d000000000000006e6f6d6f732d6d61696e6e6574030f5c6900000000" &
  "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")

func genesisStateWith(inscription: seq[byte], channelId: ChannelId):
    GenesisState =
  GenesisState(
    signedMantleTx: SignedMantleTx(
      tx: MantleTx(ops: @[
        Op(payload: OpPayload(
          kind: OpPayloadTag.ChannelInscribe,
          channelInscribe: ChannelInscribePayload(
            channelId: channelId,
            inscription: inscription)))])))

suite "chain/genesis cryptarchia parameters":
  test "decodes the spec worked example":
    let param = genesisStateWith(
      SpecInscription, default(ChannelId)
    ).cryptarchiaParameter.expect("valid inscription")
    check:
      param.chainId == "nomos-mainnet"
      param.genesisTime == 0x695c0f03'u64
      param.epochNonce.toHex ==
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

  test "rejects a truncated inscription":
    var bytes = SpecInscription
    bytes.setLen(bytes.len - 1)
    check genesisStateWith(bytes, default(ChannelId)).cryptarchiaParameter.isErr

  test "rejects a chain-id length that disagrees with the payload":
    var bytes = SpecInscription
    bytes[0] = 0x0c # claims 12 bytes; payload has 13
    check genesisStateWith(bytes, default(ChannelId)).cryptarchiaParameter.isErr

  test "ignores inscriptions on non-null channels":
    var channel: ChannelId
    channel[0] = 1
    check genesisStateWith(
      SpecInscription, channel).cryptarchiaParameter.isErr

  test "errors when the genesis tx has no inscription":
    check GenesisState().cryptarchiaParameter.isErr

{.pop.}
