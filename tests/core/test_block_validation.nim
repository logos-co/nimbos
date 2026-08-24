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
  libp2p/crypto/ed25519/ed25519,
  ./mantle/test_helpers,
  ../testutil,
  ../../logos_chain/core/[types, local_tree, mempool],
  ../../logos_chain/core/mantle/[operations, opcodes, proofs, tx_types],
  ../../logos_chain/chain/[block_validation, genesis, proposal],
  ../../logos_chain/ledger/ledger
from ../../logos_chain/core/crypto/types import FieldElement
from ../../logos_chain/core/mantle/primitives import MaxBlockTxs, SlotNumber
from ../ledger/test_helpers import testLedgerConfig
from ../ledger/sdp/test_helpers import testSdpRegistry

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


  test "rejects a transaction with mismatched ops and opProofs counts":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm
    badTx.opProofs.add(badTx.opProofs[0]) # 1 op, 2 proofs
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    check not validateBlockBody(b1)

  test "rejects a transaction with unsupported opcode":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm
    badTx.tx.ops[0].opcode = cast[Opcode](0xff'u8)
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    check not validateBlockBody(b1)

  test "rejects a transaction with opcode mismatching payload":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm
    badTx.tx.ops[0].opcode = OpChannelInscribe
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    check not validateBlockBody(b1)

  test "rejects a transaction with proof kind mismatching opcode":
    let
      sm = mkTransferTx(@[], @[])
      genesis = createGenesisBlock(sm)
    var badTx = sm
    badTx.opProofs[0] = OpProof(kind: opfChannelInscribe,
        ed25519SigProof: default(Ed25519SigProof))
    let b1 = childBlock(genesis.header, blockId(genesis.header), SlotNumber(1), [badTx])
    check not validateBlockBody(b1)


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
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      blk = childBlock(genesis.header, gid, SlotNumber(1), [sm])
      
    var proposal = new(Proposal)
    proposal[] = initProposal(blk.header, [sm], blk.signature).get()
    
    var mempool = Mempool.init()
    check mempool.add(sm, SlotNumber(0))
    
    var state = LedgerState.fromGenesis(
        genesis.txs, default(FieldElement), testSdpRegistry(),
        testLedgerConfig).expect("genesis state")
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0
    let ledger = Ledger[BlockId].init(gid, state, testLedgerConfig)
      
    check reconstructAndValidateProposal(proposal[], tree, ledger, mempool).isOk
    

  test "validateProposal rejects if referenced transaction is missing from mempool":
    let
      sm = minimalSignedTx()
      genesis = createGenesisBlock(sm)
      gid = blockId(genesis.header)
      tree = newLocalTree(genesis, 1'u64)
      blk = childBlock(genesis.header, gid, SlotNumber(1), [sm])
      
    var proposal = new(Proposal)
    proposal[] = initProposal(blk.header, [sm], blk.signature).get()
    var state = LedgerState.fromGenesis(
        genesis.txs, default(FieldElement), testSdpRegistry(),
        testLedgerConfig).expect("genesis state")
    state.feeMarket.executionBaseFee = 0
    state.feeMarket.storageGasPrice = 0
    let
      ledger = Ledger[BlockId].init(gid, state, testLedgerConfig)
      mempool = Mempool.init()
      
    let res = reconstructAndValidateProposal(proposal[], tree, ledger, mempool)
    check res.isErr and res.error == MissingReference

{.pop.}
