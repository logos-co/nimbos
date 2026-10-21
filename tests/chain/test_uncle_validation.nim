# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/sequtils,
  unittest2,
  results,
  ../testutil,
  ../logos_chain/sync/helpers,
  ../../logos_chain/core/types,
  ../../logos_chain/chain/chain
from ../../logos_chain/core/mantle/primitives import SlotNumber

type Scene = object
  # Applied chain over genesis. One block for each slot.
  chain: Chain
  genesis: ValidBlock
  blocks: seq[Block]

func rejectSlotFive(
    proof: ProofOfLeadership, public: LeaderPublic
): Result[bool, PolLoadError] =
  ok(public.slot != 5)

func signedHeader(blk: Block): SignedHeader =
  SignedHeader(header: blk.header, signature: blk.signature)

proc forkBlock(parent: Header, slot: SlotNumber, tag: byte = 1): Block =
  # Fork block over `parent`. The nonzero `tag` makes it differ from a
  # chain block at the same slot and parent.
  childBlock(parent, blockId(parent), slot, [], tag = tag)

proc carrier(parent: Block, slot: SlotNumber, uncles: openArray[SignedHeader]): Block =
  # Block over `parent` that carries `uncles`.
  childBlock(parent.header, blockId(parent.header), slot, [], uncles)

proc scene(
    slots: openArray[SlotNumber] = [1'u64, 2, 3],
    securityParam: uint64 = 10,
    verifier: LeaderProofVerifier = mockVerifyLeaderProof,
): Scene =
  # One applied block for each entry of `slots`, in order over genesis.
  # `securityParam = 10` keeps the parent states of the uncles. The default
  # of 1 prunes each state behind the immutable block.
  let
    validGenesisTx = testValidGenesisTx()
    genesis = createGenesisBlock(validGenesisTx)
  var
    s = Scene(
      chain: initTestChain(genesis, securityParam = securityParam, verifier = verifier),
      genesis: genesis,
      blocks: newSeqOfCap[Block](slots.len))
    parent = initGenesisBlock(validGenesisTx)
  for slot in slots:
    let blk = carrier(parent, slot, [])
    check s.chain.tryApplyBlock(blk).isOk
    s.blocks.add(blk)
    parent = blk
  s

proc verdict(s: Scene, blk: Block): Result[void, UncleError] =
  validateUncles(createAdmittedBlockForTest(blk), s.chain.localTree, s.chain.ledger)

proc committedState(s: Scene, blk: Block): LedgerState =
  s.chain.ledger.state(blockId(blk.header)).expect("state of an applied block")

suite "chain/uncle_validation":
  test "accepts a valid uncle received as a fork block":
    var s = scene()
    # U shares slot 2 with b2. Fails if a chain-block slot rejects the uncle.
    let u = forkBlock(s.blocks[0].header, 2)
    check s.chain.tryApplyBlock(u).isOk
    let a = carrier(s.blocks[2], 4, [signedHeader(u)])
    check s.verdict(a).isOk

  test "accepts MaxUncles uncles":
    let s = scene()
    let
      b1 = s.blocks[0]
      uncles = (1 .. MaxUncles).mapIt(
        signedHeader(forkBlock(b1.header, 2, tag = byte(it))))
      a = carrier(s.blocks[2], 4, uncles)
    check s.verdict(a).isOk

  test "accepts the same uncle twice in one block and again in the next":
    # The spec does not forbid a repeat. Fails if a dedup check rejects it.
    var s = scene()
    let
      su = signedHeader(forkBlock(s.blocks[0].header, 2))
      a = carrier(s.blocks[2], 4, [su, su])
    check s.chain.tryApplyBlock(a).isOk
    let a2 = carrier(a, 5, [su])
    check s.verdict(a2).isOk

  test "accepts an uncle header with a bedrock version other than 1":
    # The uncle rules carry no version check.
    let s = scene()
    let
      b1 = s.blocks[0]
      u = childBlock(b1.header, blockId(b1.header), 2, [], bedrockVersion = 2)
      a = carrier(s.blocks[2], 4, [signedHeader(u)])
    check s.verdict(a).isOk

  test "accepts an uncle whose parent is exactly at the window edge":
    # uncleWindowSlots is 20. The parent is at 1 and the block is at 21.
    let s = scene()
    let
      u = forkBlock(s.blocks[0].header, 2)
      a = carrier(s.blocks[2], 21, [signedHeader(u)])
    check s.verdict(a).isOk

  test "accepts an uncle whose parent is genesis":
    # Fails if the walk stops at the zero parent before it matches genesis.
    let s = scene()
    let
      u = forkBlock(s.genesis.header, 1)
      a = carrier(s.blocks[2], 4, [signedHeader(u)])
    check s.verdict(a).isOk

  test "a carried uncle adds its slot to the density and changes nothing else":
    # The epoch-0 window is [0, 59]. The uncle at slot 5 is a new occupied
    # slot. Fails if the uncle entropy leaks into the nonce.
    var
      withUncle = scene()
      plain = scene()
    let
      u = forkBlock(withUncle.blocks[0].header, 5)
      a = carrier(withUncle.blocks[2], 6, [signedHeader(u)])
      aPlain = carrier(plain.blocks[2], 6, [])
    check:
      withUncle.chain.tryApplyBlock(a).isOk
      plain.chain.tryApplyBlock(aPlain).isOk
    let
      got = withUncle.committedState(a)
      want = plain.committedState(aPlain)
    check:
      got.epochs.blockDensity.density == 5
      want.epochs.blockDensity.density == 4
      got.epochs.nonce == want.epochs.nonce
      got.epochs.lastAppliedSlot == want.epochs.lastAppliedSlot

  test "rejects an uncle at the block's slot":
    let s = scene()
    let
      u = forkBlock(s.blocks[0].header, 4)
      a = carrier(s.blocks[2], 4, [signedHeader(u)])
    check s.verdict(a).error == UncleError.NotStrictlyOlder

  test "rejects an uncle at its parent's slot":
    let s = scene()
    let
      u = forkBlock(s.blocks[0].header, 1)
      a = carrier(s.blocks[2], 4, [signedHeader(u)])
    check s.verdict(a).error == UncleError.NotAfterParent

  test "rejects an uncle whose parent is on another fork":
    var s = scene()
    let f = forkBlock(s.blocks[0].header, 2, tag = 1)
    check s.chain.tryApplyBlock(f).isOk
    let
      u = forkBlock(f.header, 3, tag = 2)
      a = carrier(s.blocks[2], 4, [signedHeader(u)])
    check s.verdict(a).error == UncleError.ParentNotOnChain

  test "rejects an uncle whose parent is older than the window":
    # The parent is at 1 and the block is at 22. That is one slot past
    # uncleWindowSlots = 20.
    let s = scene()
    let
      u = forkBlock(s.blocks[0].header, 2)
      a = carrier(s.blocks[2], 22, [signedHeader(u)])
    check s.verdict(a).error == UncleError.ParentNotOnChain

  test "rejects an uncle that is a chain block":
    # The uncle is the parent itself. Fails if the walk starts one block
    # above the parent. The block stays out of the tree.
    var s = scene()
    let
      b3 = s.blocks[2]
      a = carrier(b3, 4, [signedHeader(b3)])
      res = s.chain.tryApplyBlock(a)
    check:
      res.error.kind == BlockApplyErrorKind.UncleRejected
      res.error.uncleError == UncleError.OnChain
      not s.chain.localTree.hasBlock(blockId(a.header))
      s.chain.localTree.localTipId == blockId(b3.header)

  test "rejects a tampered signature":
    let s = scene()
    var su = signedHeader(forkBlock(s.blocks[0].header, 2))
    su.signature.data[0] = su.signature.data[0] xor 0xff'u8
    let a = carrier(s.blocks[2], 4, [su])
    check s.verdict(a).error == UncleError.InvalidSignature

  test "rejects a failing proof":
    let s = scene(verifier = rejectSlotFive)
    let
      u = forkBlock(s.blocks[0].header, 5)
      a = carrier(s.blocks[2], 6, [signedHeader(u)])
    check s.verdict(a).error == UncleError.InvalidProof

  test "accepts an uncle whose parent is the immutable block":
    # securityParam = 1: after three blocks the immutable block is b2 and
    # its state is the retained anchor. Fails if pruning drops the LIB state.
    let s = scene(securityParam = 1)
    let
      b2 = s.blocks[1]
      u = forkBlock(b2.header, 3)
      a = carrier(s.blocks[2], 4, [signedHeader(u)])
    check:
      s.chain.localTree.latestImmutableBlockId() == blockId(b2.header)
      s.verdict(a).isOk

  test "rejects an uncle whose parent state was pruned":
    # securityParam = 1: after three blocks the immutable block is b2 and
    # the states of b1 and genesis are gone, while their headers stay.
    # The 20-slot window exceeds k, as it does in the devnet config.
    let s = scene(securityParam = 1)
    let
      b1 = s.blocks[0]
      u = forkBlock(b1.header, 2)
      a = carrier(s.blocks[2], 4, [signedHeader(u)])
    check:
      s.chain.localTree.hasBlock(blockId(b1.header))
      s.chain.ledger.state(blockId(b1.header)).isNone
      s.verdict(a).error == UncleError.ParentNotOnChain

  test "rejects a list with one valid and one invalid entry":
    let s = scene()
    let
      b1 = s.blocks[0]
      good = signedHeader(forkBlock(b1.header, 2))
      late = signedHeader(forkBlock(b1.header, 4))
      a = carrier(s.blocks[2], 4, [good, late])
    check s.verdict(a).error == UncleError.NotStrictlyOlder

  test "an orphan with a bad uncle is rejected on replay when its parent arrives":
    # Fails if the uncle check runs only at admission.
    var s = scene(slots = [1'u64, 2])
    let
      b2 = s.blocks[1]
      b3 = carrier(b2, 3, [])
      a = carrier(b3, 4, [signedHeader(b2)])
    check:
      s.chain.tryApplyBlock(a).error.kind == BlockApplyErrorKind.OrphanBuffered
      s.chain.tryApplyBlock(b3).isOk
    let
      children = s.chain.orphanPool.takeChildren(blockId(b3.header))
      res = s.chain.tryApplyAdmittedBlock(children[0])
    check:
      res.error.kind == BlockApplyErrorKind.UncleRejected
      res.error.uncleError == UncleError.OnChain
      not s.chain.localTree.hasBlock(blockId(a.header))

{.pop.}
