# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  ../testutil,
  ./mantle/test_helpers,
  ../../logos_chain/core/types,
  ../../logos_chain/core/mantle/[operations, opcodes, proofs, tx_types],
  ../../logos_chain/chain/block_validation,
  ../../logos_chain/chain/genesis
from ../../logos_chain/core/mantle/primitives import SlotNumber

suite "core/block_validation":
  test "accepts a structurally valid block":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    check validateBlock(b1)

  test "rejects wrong bedrock version":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.header.bedrockVersion = 99'u8
    check not validateBlock(b1)

  test "rejects a block root that disagrees with the transactions":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.header.blockRoot[0] = b1.header.blockRoot[0] xor 0xff'u8
    check not validateBlock(b1)

  test "rejects a block exceeding MaxBlockTxs":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
    var txs = newSeq[SignedMantleTx](MaxBlockTxs + 1)
    for i in 0 ..< txs.len:
      txs[i] = sm
    let b1 = Block(
      header: genesis.header,
      signature: genesis.signature,
      txs: txs
    )
    expect(AssertionDefect):
      discard validateBlock(b1)

  test "rejects a transaction with mismatched ops and opProofs counts":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm
    badTx.opProofs.add(badTx.opProofs[0]) # 1 op, 2 proofs
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    expect(AssertionDefect):
      discard validateBlock(b1)

  test "rejects a transaction with unsupported opcode":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm
    badTx.tx.ops[0].opcode = cast[Opcode](0xff'u8)
    let b1 = Block(
      header: genesis.header,
      signature: genesis.signature,
      txs: @[badTx]
    )
    check not validateBlock(b1)

  test "rejects a transaction with opcode mismatching payload":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm
    badTx.tx.ops[0].opcode = OpChannelInscribe
    let b1 = Block(
      header: genesis.header,
      signature: genesis.signature,
      txs: @[badTx]
    )
    check not validateBlock(b1)

  test "rejects a transaction with proof kind mismatching opcode":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm
    badTx.opProofs[0] = OpProof(kind: opfChannelInscribe, ed25519SigProof: default(Ed25519SigProof))
    let b1 = Block(
      header: genesis.header,
      signature: genesis.signature,
      txs: @[badTx]
    )
    check not validateBlock(b1)

  test "rejects a block payload exceeding MaxBlockSize":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      largePayload = ChannelInscribePayload(
        channelId: default(ChannelId),
        inscription: newSeq[byte](MaxBlockSize + 1),
        parent: default(Parent),
        signer: default(Signer),
      )
      largeOp = createChannelInscribeOp(largePayload)
      largeTx = SignedMantleTx(
        tx: MantleTx(ops: @[largeOp]),
        opProofs: @[OpProof(kind: opfChannelInscribe, ed25519SigProof: default(Ed25519SigProof))],
      )
    let b1 = Block(
      header: genesis.header,
      signature: genesis.signature,
      txs: @[largeTx]
    )
    check not validateBlock(b1)

{.pop.}
