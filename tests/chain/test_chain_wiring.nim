# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## End-to-end epoch wiring against the real devnet deployment settings:
## settings → LedgerConfig, genesis block → ceremony seed, and a seeded
## genesis ledger state (exercising the f = 1/20 lottery constants on the
## actual devnet configuration).

# `gcsafe` deliberately omitted: `parseDeploymentSettings` (YAML) is not
# GC-safe, matching `tests/chain/test_devnet_genesis_mantle_tx.nim`.
{.push raises: [].}
{.used.}

import
  std/[os, strutils, times],
  unittest2,
  stew/[byteutils, io2],
  libp2p/crypto/ed25519/ed25519,
  ../testutil,
  ../../logos_chain/chain/chain,
  ../../logos_chain/deployment/deployment_settings,
  ../../logos_chain/zk/poseidon2/hasher

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  deploymentSettingsPath = testsDir / "../../config/deployment-settings.yaml"

proc initZeroFeeChain(ds: DeploymentSettings): Chain =
  var chain = Chain.init(ds, mockVerifyLeaderProof).expect("chain init")
  chain.slotConfig.genesisTime = uint64(getTime().toUnix() - 100)
  let gid = blockId(chain.genesisBlock.header)
  var s = chain.ledger.state(gid).get()
  s.feeMarket.executionBaseFee = 0
  s.feeMarket.storageGasPrice = 0
  chain.ledger.commitUpdate(gid, s)
  chain

suite "chain/epoch wiring (devnet deployment settings)":
  setup:
    let
      dsText = readAllChars(deploymentSettingsPath).valueOr:
        check false
        return
      ds = parseDeploymentSettings(dsText).valueOr:
        check false
        return

  test "ledgerConfig derives the devnet schedule":
    let cfg = ledgerConfig(ds)
    check:
      # k = 30, f = 1/20 → base period 600, epoch length 6000, TSI window 3600
      cfg.epochSchedule.basePeriodLength == 600
      cfg.epochSchedule.epochLength == 6000
      cfg.epochSchedule.nonceContributionPeriod == 3600
      cfg.slotActivationCoeff == NonNegativeRatio(num: 1, den: 20)
      cfg.learningRateFixed == 500 # fixedPoint(0.5)

  test "cryptarchiaParameter decodes the devnet ceremony values":
    let
      param = ds.cryptarchia.genesisState.cryptarchiaParameter().valueOr:
        check false
        return
      # Nonce derived by the ceremony from its pinned entropy_sources input.
      ceremonyNonce = frFromBytesLE(hexToByteArray[32](
        "2d2ddf918544bca603c5a291c7dd1b902d6769ff4b00021506780e075c06051a"
      )).expect("below the BN254 order")
    check:
      param.genesisTime == 0x69fe6991'u64
      param.epochNonce == ceremonyNonce

  test "fromGenesis builds a lottery-ready genesis state":
    let
      param = ds.cryptarchia.genesisState.cryptarchiaParameter().valueOr:
        check false
        return
      state = LedgerState.fromGenesis(
        [ds.cryptarchia.genesisState.signedMantleTx], param.epochNonce,
        SdpRegistry.init(ds.cryptarchia.sdpConfig), ledgerConfig(ds)).valueOr:
        check false
        return
    check:
      # Standalone ceremony notes (100000 + 100 + 100 + 1) plus the faucet note.
      state.latestUtxos.len == 5
      state.epochs.activeEpoch.epoch == 0
      state.epochs.nextEpoch.epoch == 1
      # faucet-filtered sum: the ~2^64 faucet mint is excluded.
      state.epochs.activeEpoch.totalStake == 100201
      state.epochs.activeEpoch.lottery0 != default(FieldElement)
      state.epochs.activeEpoch.lottery1 != default(FieldElement)
      state.epochs.blockDensity.periodStart == 0
      state.epochs.blockDensity.periodEnd == 3599

  test "Chain.init wires ledger, epoch state and clock from settings":
    let chain = Chain.init(ds, mockVerifyLeaderProof).valueOr:
      check false
      return
    let genesisState = chain.ledger.state(
      blockId(chain.genesisBlock.header)).valueOr:
      check false
      return
    check:
      chain.slotConfig.genesisTime == 0x69fe6991'u64
      chain.slotConfig.slotDurationSeconds == 1
      genesisState.latestUtxos.len == 5
      genesisState.epochs.activeEpoch.totalStake == 100201
      genesisState.epochs.nextEpoch.epoch == 1
      chain.currentWallclockSlot() > 0 # devnet genesis lies in the past

  test "tryApplyBlock ingests a child of genesis end-to-end":
    var chain = Chain.init(ds, mockVerifyLeaderProof).valueOr:
      check false
      return
    let
      gid = blockId(chain.genesisBlock.header)
      b1 = childBlock(chain.genesisBlock.header, gid, SlotNumber(1), [])
      id1 = blockId(b1.header)
    check:
      chain.tryApplyBlock(b1).isOk
      chain.ledger.state(id1).isSome
      chain.localTree.localTipId == id1
    let dup = chain.tryApplyBlock(b1)
    check dup.isErr and dup.error.kind == BlockApplyErrorKind.AlreadyApplied

  test "tryApplyBlock rejects a slot beyond the wallclock":
    var chain = Chain.init(ds, mockVerifyLeaderProof).valueOr:
      check false
      return
    let
      gid = blockId(chain.genesisBlock.header)
      b1 = childBlock(
        chain.genesisBlock.header, gid, high(SlotNumber) - 1, [])
      r = chain.tryApplyBlock(b1)
    check r.isErr and r.error.kind == BlockApplyErrorKind.FutureSlot

  test "tryApplyBlock rejects an unknown parent at tree admission":
    var chain = Chain.init(ds, mockVerifyLeaderProof).valueOr:
      check false
      return
    var fakeParent: BlockId
    fakeParent[0] = 7'u8
    let
      orphan = childBlock(
        chain.genesisBlock.header, fakeParent, SlotNumber(1), [])
      r = chain.tryApplyBlock(orphan)
    check:
      r.isErr
      r.error.kind == BlockApplyErrorKind.TreeRejected

  test "tryApplyBlock removes block txs from mempool, re-adds on fork switch, and selects restored txs":
    var chain = initZeroFeeChain(ds)

    # 1. Add tx to mempool
    let dummyTx = signedTxWithOps(1, 1)
    let txHash = mantleTxHash(dummyTx.tx)
    check chain.mempool.add(dummyTx, SlotNumber(0)) == true
    check txHash in chain.mempool

    # 2. Ingest block b1 containing dummyTx
    let gid = blockId(chain.genesisBlock.header)
    let b1 = childBlock(chain.genesisBlock.header, gid, SlotNumber(1), [dummyTx])
    let id1 = blockId(b1.header)
    check chain.tryApplyBlock(b1).isOk
    check chain.localTree.localTipId == id1

    # Immediate removal upon block addition
    check txHash notin chain.mempool

    # 3. Build a longer fork (b2_fork at slot 2 from genesis, b3_fork at slot 3 from b2_fork)
    let b2_fork = childBlock(chain.genesisBlock.header, gid, SlotNumber(2), [])
    let id2_fork = blockId(b2_fork.header)
    check chain.tryApplyBlock(b2_fork).isOk
    # b2_fork height 1 is not strictly higher than b1 height 1, so tip remains id1
    check chain.localTree.localTipId == id1
    check txHash notin chain.mempool

    # Add b3_fork extending b2_fork -> height 2 > height 1, triggering fork switch!
    let b3_fork = childBlock(b2_fork.header, id2_fork, SlotNumber(3), [])
    let id3_fork = blockId(b3_fork.header)
    check chain.tryApplyBlock(b3_fork).isOk
    check chain.localTree.localTipId == id3_fork

    # Fork switch re-added dummyTx from the forked-off branch b1 back into mempool!
    check txHash in chain.mempool

    # Proposal selection on the new tip picks up the restored dummyTx
    let selected = chain.mempool.selectTxsForProposal(
      chain.ledger.state(id3_fork).get, ledgerConfig(ds),
      chain.currentWallclockSlot() + MempoolMinAgeSlots
    )
    check selected.len == 1
    check mantleTxHash(selected[0].tx) == txHash

  test "multi-fork reorg correctly handles multiple competing branches":
    var chain = initZeroFeeChain(ds)

    let gid = blockId(chain.genesisBlock.header)
    let tx1 = signedTxWithOps(1, 101)
    let tx2 = signedTxWithOps(1, 102)
    let tx3 = signedTxWithOps(1, 103)
    let h1 = mantleTxHash(tx1.tx)
    let h2 = mantleTxHash(tx2.tx)
    let h3 = mantleTxHash(tx3.tx)

    check chain.mempool.add(tx1, SlotNumber(0))
    check chain.mempool.add(tx2, SlotNumber(0))
    check chain.mempool.add(tx3, SlotNumber(0))

    # Branch A: Genesis -> A1 (contains tx1) -> A2 (contains tx2) (height 2)
    let a1 = childBlock(chain.genesisBlock.header, gid, SlotNumber(1), [tx1])
    let idA1 = blockId(a1.header)
    check chain.tryApplyBlock(a1).isOk
    let a2 = childBlock(a1.header, idA1, SlotNumber(2), [tx2])
    let idA2 = blockId(a2.header)
    check chain.tryApplyBlock(a2).isOk
    check chain.localTree.localTipId == idA2

    # tx1 and tx2 removed from mempool
    check h1 notin chain.mempool
    check h2 notin chain.mempool
    check h3 in chain.mempool

    # Branch B: Genesis -> B1 -> B2 -> B3 (contains tx3) (height 3 > height 2)
    let b1 = childBlock(chain.genesisBlock.header, gid, SlotNumber(3), [])
    let idB1 = blockId(b1.header)
    check chain.tryApplyBlock(b1).isOk
    let b2 = childBlock(b1.header, idB1, SlotNumber(4), [])
    let idB2 = blockId(b2.header)
    check chain.tryApplyBlock(b2).isOk
    let b3 = childBlock(b2.header, idB2, SlotNumber(5), [tx3])
    let idB3 = blockId(b3.header)
    check chain.tryApplyBlock(b3).isOk
    check chain.localTree.localTipId == idB3

    # Reorg from Branch A to Branch B: tx1 and tx2 restored, tx3 removed
    check h1 in chain.mempool
    check h2 in chain.mempool
    check h3 notin chain.mempool

  test "tryApplyBlock prunes orphaned fork states from localTree and ledger upon finalization":
    var dsSmallSec = ds
    dsSmallSec.cryptarchia.securityParam = 2
    var chain = initZeroFeeChain(dsSmallSec)
    let gid = blockId(chain.genesisBlock.header)

    # Branch A: Genesis -> A1 (slot 1) (height 1)
    let a1 = childBlock(chain.genesisBlock.header, gid, SlotNumber(1), [])
    let idA1 = blockId(a1.header)
    check chain.tryApplyBlock(a1).isOk
    check chain.localTree.localTipId == idA1

    # Branch B: Genesis -> B1 (slot 2) -> B2 (slot 3) -> B3 (slot 4)
    let b1 = childBlock(chain.genesisBlock.header, gid, SlotNumber(2), [])
    let idB1 = blockId(b1.header)
    check chain.tryApplyBlock(b1).isOk
    let b2 = childBlock(b1.header, idB1, SlotNumber(3), [])
    let idB2 = blockId(b2.header)
    check chain.tryApplyBlock(b2).isOk
    let b3 = childBlock(b2.header, idB2, SlotNumber(4), [])
    let idB3 = blockId(b3.header)
    check chain.tryApplyBlock(b3).isOk
    check chain.localTree.localTipId == idB3

    # With securityParam = 2 and tip height = 3, LIB advances to B1 (height 3 - 2 = 1).
    # Orphaned Fork A block A1 at height 1 is pruned from both tree and ledger.
    check not chain.localTree.hasBlock(idA1)
    check chain.ledger.state(idA1).isNone

    # Canonical branch B blocks remain in both tree and ledger.
    check chain.localTree.hasBlock(idB1)
    check chain.localTree.hasBlock(idB2)
    check chain.localTree.hasBlock(idB3)
    check chain.ledger.state(idB1).isSome
    check chain.ledger.state(idB2).isSome
    check chain.ledger.state(idB3).isSome

  test "selectTxsForProposal automatically advances epochs across boundaries":
    var chain = initZeroFeeChain(ds)
    # Set genesis in the past so slot 6500 is within current wallclock
    chain.slotConfig.genesisTime = uint64(getTime().toUnix() - 7000)

    let gid = blockId(chain.genesisBlock.header)
    let tx = signedTxWithOps(1, 101)
    check chain.mempool.add(tx, SlotNumber(0))

    let tipState = chain.ledger.state(gid).get()
    check tipState.epochs.activeEpoch.epoch == 0

    # Proposal at slot 6500 crosses epoch 0 (epoch length = 6000 slots)
    let selected = chain.mempool.selectTxsForProposal(
      tipState, ledgerConfig(ds), SlotNumber(6500)
    )
    check selected.len == 1
    check mantleTxHash(selected[0].tx) == mantleTxHash(tx.tx)

    # Verify that a block constructed from this proposal is valid and admitted to localTree & ledger
    let blk = childBlock(chain.genesisBlock.header, gid, SlotNumber(6500), selected)
    let blkId = blockId(blk.header)
    check chain.tryApplyBlock(blk).isOk
    check chain.localTree.hasBlock(blkId)
    check chain.localTree.localTipId == blkId

    # Verify that the post-application ledger state has officially transitioned to Epoch 1
    let appliedState = chain.ledger.state(blkId).get()
    check appliedState.epochs.activeEpoch.epoch == 1
    check appliedState.epochs.nextEpoch.epoch == 2

{.pop.}
