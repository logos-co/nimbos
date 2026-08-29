# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to these terms.

{.push raises: [], gcsafe.}
{.used.}

import
  bearssl/rand,
  libp2p/crypto/ed25519/ed25519,
  unittest2,
  ../testutil,
  ./mantle/test_helpers,
  ../../logos_chain/core/types,
  ../../logos_chain/core/mantle/[operations, opcodes, proofs, tx_types, tx_hashing],
  ../../logos_chain/chain/block_validation,
  ../../logos_chain/chain/genesis
from ../../logos_chain/core/mantle/primitives import MaxBlockTxs, SlotNumber

const inscribeTxFraming = 166
  ## OpCount, Opcode, ChannelId, the u32 inscription length, Parent, Signer
  ## and the 64-byte Ed25519 proof — everything but the inscription itself.

proc mkSizedTx(bytes: int): SignedMantleTx =
  ## ChannelInscribe transaction padded to encode to exactly `bytes`.
  doAssert bytes >= inscribeTxFraming
  let
    rng = HmacDrbgContext.new()
    kp = mkEdKeyPair(rng)
    tx = MantleTx(ops: @[createChannelInscribeOp(ChannelInscribePayload(
      channelId: default(ChannelId),
      inscription: newSeq[byte](bytes - inscribeTxFraming),
      parent: default(Parent),
      signer: kp.pubkey,
    ))])
    txHash = mantleTxHash(tx)
    sig = sign(kp.seckey, txHash)
  SignedMantleTx(
    tx: tx,
    opProofs: @[OpProof(kind: opfChannelInscribe, ed25519SigProof: sig)],
  )

suite "core/block_validation":
  test "accepts a structurally valid block":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    check validateBlock(b1).isOk

  test "rejects wrong bedrock version":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.header.bedrockVersion = 99'u8
    check validateBlock(b1).isErr

  test "rejects a block root that disagrees with the transactions":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
    var b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [sm])
    b1.header.blockRoot[0] = b1.header.blockRoot[0] xor 0xff'u8
    check validateBlock(b1).isErr

  test "rejects a transaction with mismatched ops and opProofs counts":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm
    badTx.opProofs.add(badTx.opProofs[0]) # 1 op, 2 proofs
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    check validateBlockBody(b1).isErr

  test "rejects a transaction with unsupported opcode":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm
    badTx.tx.ops[0].opcode = cast[Opcode](0xff'u8)
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    check validateBlockBody(b1).isErr

  test "rejects a transaction with opcode mismatching payload":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm
    badTx.tx.ops[0].opcode = OpChannelInscribe
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    check validateBlockBody(b1).isErr

  test "rejects a transaction with proof kind mismatching opcode":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm
    badTx.opProofs[0] = OpProof(kind: opfChannelInscribe,
        ed25519SigProof: default(Ed25519SigProof))
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    check validateBlockBody(b1).isErr

suite "core/block_validation — inclusive size and count bounds":
  test "a block whose tx bytes are exactly MaxBlockSize is accepted":
    let
      genesis = createGenesisBlock(minimalSignedTx())
      # Only the serialized transactions count; header and block signature don't.
      tx = mkSizedTx(MaxBlockSize)
    check encodeSignedMantleTx(tx).len == MaxBlockSize
    let b1 = childBlock(
      genesis.header, blockId(genesis.header), SlotNumber(1), [tx])
    check validateBlock(b1).isOk

  test "one byte past MaxBlockSize is rejected":
    let
      genesis = createGenesisBlock(minimalSignedTx())
      tx = mkSizedTx(MaxBlockSize + 1)
      b1 = childBlock(
        genesis.header, blockId(genesis.header), SlotNumber(1), [tx])
    check validateBlock(b1).isErr

  test "a block with exactly MaxBlockTxs transactions is accepted":
    let
      genesis = createGenesisBlock(minimalSignedTx())
      txs = newSeq[SignedMantleTx](MaxBlockTxs)
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), txs)
    check validateBlock(b1).isOk

  test "one transaction past MaxBlockTxs is rejected":
    let
      genesis = createGenesisBlock(minimalSignedTx())
      txs = newSeq[SignedMantleTx](MaxBlockTxs)
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), txs)
      overLong = Block(
        header: b1.header,
        signature: b1.signature,
        txs: newSeq[SignedMantleTx](MaxBlockTxs + 1),
      )
    check validateBlock(overLong).isErr

{.pop.}
