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
  unittest2,
  libp2p/crypto/ed25519/ed25519,
  ./mantle/test_helpers,
  ../testutil,
  ../../logos_chain/core/[types, block_validation, local_tree, mempool],
  ../../logos_chain/core/mantle/[operations, proofs, tx_types],
  ../../logos_chain/chain/genesis
from ../../logos_chain/core/mantle/primitives import MaxBlockTxs, SlotNumber

const inscribeTxFraming = 166
  ## OpCount, Opcode, ChannelId, the u32 inscription length, Parent, Signer
  ## and the 64-byte Ed25519 proof — everything but the inscription itself.

func mkSizedTx(bytes: int): SignedMantleTx =
  ## ChannelInscribe transaction padded to encode to exactly `bytes`.
  doAssert bytes >= inscribeTxFraming
  SignedMantleTx(
    tx: MantleTx(ops: @[createChannelInscribeOp(ChannelInscribePayload(
      channelId: default(ChannelId),
      inscription: newSeq[byte](bytes - inscribeTxFraming),
      parent: default(Parent),
      signer: default(Signer),
    ))]),
    opProofs: @[defaultOpProofForOpcode(OpChannelInscribe)],
  )

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

suite "core/block_validation — inclusive size and count bounds":
  test "a block whose tx bytes are exactly MaxBlockSize is accepted":
    let
      genesis = createGenesisBlock(minimalSignedTx())
      # Only the serialized transactions count; header and block signature don't.
      tx = mkSizedTx(MaxBlockSize)
    check encodeSignedMantleTx(tx).len == MaxBlockSize
    let b1 = childBlock(
      genesis.header, blockId(genesis.header), SlotNumber(1), [tx])
    check validateBlock(b1)

  test "one byte past MaxBlockSize is rejected":
    let
      genesis = createGenesisBlock(minimalSignedTx())
      tx = mkSizedTx(MaxBlockSize + 1)
      b1 = childBlock(
        genesis.header, blockId(genesis.header), SlotNumber(1), [tx])
    check not validateBlock(b1)

  test "a block with exactly MaxBlockTxs transactions is accepted":
    let
      genesis = createGenesisBlock(minimalSignedTx())
      txs = newSeq[SignedMantleTx](MaxBlockTxs)
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), txs)
    check validateBlock(b1)

  test "one transaction past MaxBlockTxs is rejected":
    # `initBlock` and `createBlockRoot` refuse to build an over-long block, so
    # this models a decoded, untrusted one. The count check runs ahead of the
    # block-root check, which the extra transaction would also fail.
    let
      genesis = createGenesisBlock(minimalSignedTx())
      txs = newSeq[SignedMantleTx](MaxBlockTxs)
      b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), txs)
      overLong = Block(
        header: b1.header,
        signature: b1.signature,
        txs: newSeq[SignedMantleTx](MaxBlockTxs + 1),
      )
    check not validateBlock(overLong)

  test "validateProposal reconstructs block and validates it":
    let
      rng = HmacDrbgContext.new()
      kp = mkEdKeyPair(rng)
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
      blk = childBlock(genesis.header, gid, SlotNumber(1), [sm])
      
    var header = blk.header
    header.proofOfLeadership.leaderKey = kp.pubkey
    
    let signature = kp.seckey.sign(blockId(header))
    let proposal = initProposal(header, [sm], signature).get()
    
    var mempool = Mempool.init()
    check mempool.add(sm)
    
    check reconstructAndValidateProposal(proposal, tree, mempool).isSome
    
  test "validateProposal rejects if signature is invalid":
    let
      rng = HmacDrbgContext.new()
      kp1 = mkEdKeyPair(rng)
      kp2 = mkEdKeyPair(rng)
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
      blk = childBlock(genesis.header, gid, SlotNumber(1), [sm])
      
    var header = blk.header
    header.proofOfLeadership.leaderKey = kp1.pubkey
    
    let signature = kp2.seckey.sign(blockId(header))
    let proposal = initProposal(header, [sm], signature).get()
    
    var mempool = Mempool.init()
    check mempool.add(sm)
    
    check reconstructAndValidateProposal(proposal, tree, mempool).isNone

  test "validateProposal rejects if referenced transaction is missing from mempool":
    let
      rng = HmacDrbgContext.new()
      kp = mkEdKeyPair(rng)
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis)
      blk = childBlock(genesis.header, gid, SlotNumber(1), [sm])
      
    var header = blk.header
    header.proofOfLeadership.leaderKey = kp.pubkey
    
    let signature = kp.seckey.sign(blockId(header))
    let proposal = initProposal(header, [sm], signature).get()
    let mempool = Mempool.init()
    
    check reconstructAndValidateProposal(proposal, tree, mempool).isNone

{.pop.}
