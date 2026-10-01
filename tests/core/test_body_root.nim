# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec vectors for `merkle_root`, `body_root`, the canonical header encoding
## and the block ID (Cryptarchia v1 "Test Vectors").

{.push raises: [], gcsafe.}
{.used.}

import
  std/[algorithm, sequtils],
  bincode,
  stew/byteutils,
  unittest2,
  ../../logos_chain/core/types,
  ../../logos_chain/sync/types as sync_types

const
  cfg = cryptarchiaSyncBincodeConfig
  merkleLeavesHex = [
    "6ab0046084f3ce8dad90eb28afe5692ad92d5d0588a4e868ad38d0d841d7a60e", # Transfer
    "15c4361f33089c446b8f2f7747ec211d5d031da529a3ee6b62e9df670f996dbf", # ChannelConfig
    "50e5674eea7fa17f531a51159ea7c3cab843fb1c8e8bf9bd5518a8aad08865d3", # ChannelInscribe
    "d52da59d9db42391363d6c4f96447536e5dfff747b91b88320310b07581a8dee", # ChannelDeposit
    "6f57c77dc872cc3f01380fbd57a97e9f7998a1cd8b24e84594ceba796cfa0822", # ChannelWithdraw
    "2c04be946507e2b8c239b85b03cf476a8be5af8e4de853660d0447a46ea460fc", # ChannelTransfer
    "9ce9fa694b4c801eca6c9a1d3dca6401952404bda8c144fb16e03e3872fd475e", # SDPDeclare
    "3555b3d8f5d05ea5d69efb17aab7639474738bcb4bfee8d354107433d781ef9c", # SDPWithdraw
    "0a91ab8271016f212061e6b45ea35c95cfa0f9a70c5225508f284b2657f4d931", # SDPActive
    "c992f1a63a7ea665a3766fae6b032df3db12ef386caf0ef1f3654afedbc51c6c", # LeaderClaim
  ]
  expectedMerkleRootHex =
    "65f481d9f0cdb38f2166299c40f4e74bec7332df72281daec7a6547a098ff08b"
  emptyUnclesBodyRootHex =
    "d279012d8ce1c7db4812b900c29174f2657b3fa243270fc8ebeeb5f1c0a29cec"
  twoUnclesBodyRootHex =
    "7f3854d9c24cfdb5e30f37a74ace03d06adacbf807d55a89e4935d90f286e831"
  uncle0Hex =
    "016666666666666666666666666666666666666666666666666666666666666666660000000000000066666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666660000000000000000000000000000000000000000000000000000000000000034b4d9043156cb6dcf0beb0a2949b7559c940d2bcb6dbe8c53a9b30278e3a7466600000000000000000000000000000000000000000000000000000000000000563913f1ba7ad4129a077acd56278e743fd45120226dd315fa49f3a9c5d07af6a174ab84d4555a279afe053e79c8bb794be3f7d2e71e92b8da1b490687cb8306"
  uncle1Hex =
    "0177777777777777777777777777777777777777777777777777777777777777777700000000000000777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777700000000000000000000000000000000000000000000000000000000000000c853ad0f0cd2b619aea92ceec4fd56a24d6499d584ce79257e45cfd8139b60a77700000000000000000000000000000000000000000000000000000000000000ad17e45d503a16fb41c25c4b3025956c63b31015871e957f3562b47cebce784e5b392ce3dd05214afe09102e0d2ed8211a83b81f18231963a226198fd528df0c"
  leaderKeyHex =
    "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
  expectedBlockIdHex =
    "b5232b5462d6d802b2e77185e3fd7124af713e36818db1438d921e8c980232bb"

template uncle(hex: string): SignedHeader =
  decode(hexToSeqByte(hex), SignedHeader, cfg)

func vectorHeader(): Header {.raises: [ValueError].} =
  # Header row of the spec table.
  var
    parent: BlockId
    pol: ProofOfLeadership
  parent.fill(0x11'u8)
  pol.proof.fill(0x22'u8)
  pol.entropyContribution[0] = 0x55'u8
  pol.entropyContribution[1] = 0x55'u8
  pol.leaderVoucher[0] = 0x44'u8
  pol.leaderVoucher[1] = 0x44'u8
  pol.leaderKey = Ed25519PublicKey(data: hexToByteArray[32](leaderKeyHex))
  Header(
    bedrockVersion: 1'u8,
    parentBlock: parent,
    slot: 42'u64,
    bodyRoot: Hash32.fromHex(emptyUnclesBodyRootHex),
    proofOfLeadership: pol)

suite "core/body_root (spec vectors)":
  test "merkle_root of no transactions is the zero hash":
    check merkle_root(openArray[Hash32]([])) == default(Hash32)

  test "merkle_root over the ten operation-kind leaves":
    let leaves = merkleLeavesHex.mapIt(Hash32.fromHex(it))
    check toHex(merkle_root(leaves)) == expectedMerkleRootHex

  test "body_root over no uncles":
    check toHex(body_root([], Hash32.fromHex(expectedMerkleRootHex))) ==
      emptyUnclesBodyRootHex

  test "body_root over two uncles":
    let
      u0 = uncle(uncle0Hex)
      u1 = uncle(uncle1Hex)
      root = Hash32.fromHex(expectedMerkleRootHex)
    check toHex(body_root([u0, u1], root)) == twoUnclesBodyRootHex

  test "uncle order changes body_root":
    let
      u0 = uncle(uncle0Hex)
      u1 = uncle(uncle1Hex)
      root = Hash32.fromHex(expectedMerkleRootHex)
    check body_root([u1, u0], root) != body_root([u0, u1], root)

  test "encodeSignedHeader reproduces the spec uncle bytes":
    check toHex(encodeSignedHeader(uncle(uncle0Hex))) == uncle0Hex
    check toHex(encodeSignedHeader(uncle(uncle1Hex))) == uncle1Hex

  test "block ID of the header vector":
    check toHex(blockId(vectorHeader())) == expectedBlockIdHex

  test "encodeHeader is 297 bytes and equals the bincode encoding":
    let
      h = vectorHeader()
      wire = encodeHeader(h)
    check wire.len == HeaderSize
    check @wire == encode(h, cfg)

  test "encodeHeader places every field at its spec offset":
    let wire = encodeHeader(vectorHeader())
    check wire[0] == 1'u8
    check wire[1] == 0x11'u8 and wire[32] == 0x11'u8
    check wire[33] == 42'u8 and wire[40] == 0'u8
    check wire.toOpenArray(41, 72) == Hash32.fromHex(emptyUnclesBodyRootHex)
    check wire[73] == 0x22'u8 and wire[200] == 0x22'u8
    check wire[201] == 0x55'u8 and wire[232] == 0'u8
    check wire.toOpenArray(233, 264) == hexToByteArray[32](leaderKeyHex)
    check wire[265] == 0x44'u8 and wire[296] == 0'u8

{.pop.}
