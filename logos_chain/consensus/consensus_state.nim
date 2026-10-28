# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [Cryptarchia Fork Choice Rule](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/fork-choice.md)
## Spec: [Cryptarchia Bootstrapping & Synchronization](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/cryptarchia-v1-bootstr-sync.md)

{.push raises: [], gcsafe.}

import
  minilru,
  results

from ../core/crypto/types as crypto_types import isZero
from ../core/mantle/primitives import SlotNumber
from ../core/types import BlockId, Header, Block, Tip, blockId, BlockNumber
from ../chain/block_validation import ValidBlock, header
from ../chain/local_tree import
  LocalTree, init, fetchHeader, blockHeight, lcaBlockIdAndHeight,
  ancestorAtHeight, pruneForks, countChainDensity, isAncestor, hasBlock,
  addBlockToTree, getBlock

const
  DensityCacheCapacity = 512

type
  ForkChoiceRule* {.pure.} = enum
    Online    ## Ouroboros Praos rule: longest chain for shallow forks (<= k), rejects deep forks (> k)
    Bootstrap ## Ouroboros Genesis rule: longest chain for shallow forks (<= k), density check within s_gen window for deep forks (> k)

  DensityCacheKey = object
    ## Keyed by (tipId, lcaSlot). On any valid chain leading to tipId, block slots are strictly
    ## monotonic (blk.slot > parent.slot), guaranteeing at most one ancestor at lcaSlot and
    ## uniquely identifying the fork point and lcaHeight without requiring a 32-byte BlockId.
    tipId: BlockId
    lcaSlot: SlotNumber

  ForkChoiceDensityCache = ref object
    lru: LruCache[DensityCacheKey, uint64]

  ConsensusState* = ref object
    localTree: LocalTree
    canonicalTip: Tip
    latestImmutableId: BlockId
    forkChoiceRule: ForkChoiceRule
    securityParam: uint64
    densitySlotWindow: uint64
    cache: ForkChoiceDensityCache

when defined(unittest) or defined(test):
  func securityParam*(cs: ConsensusState): uint64
  func latestImmutableHeight*(cs: ConsensusState): uint64
  proc preferCandidate*(cs: ConsensusState, currentTipId, candidateId: BlockId): bool
  proc tryUpdateTip*(cs: ConsensusState, candidateId: BlockId)
else:
  func securityParam(cs: ConsensusState): uint64
  func latestImmutableHeight(cs: ConsensusState): uint64
  proc preferCandidate(cs: ConsensusState, currentTipId, candidateId: BlockId): bool
  proc tryUpdateTip(cs: ConsensusState, candidateId: BlockId)

func init(T: type ForkChoiceDensityCache): T =
  T(lru: LruCache[DensityCacheKey, uint64].init(DensityCacheCapacity))

func hasBlock*(cs: ConsensusState, id: BlockId): bool =
  cs.localTree.hasBlock(id)

func getBlock*(cs: ConsensusState, id: BlockId): Opt[ValidBlock] =
  cs.localTree.getBlock(id)

func fetchHeader*(cs: ConsensusState, id: BlockId): Opt[Header] =
  cs.localTree.fetchHeader(id)

func blockHeight*(cs: ConsensusState, id: BlockId): Opt[BlockNumber] =
  cs.localTree.blockHeight(id)

func lcaBlockIdAndHeight*(
    cs: ConsensusState, a, b: BlockId,
): Opt[(BlockId, BlockNumber)] =
  cs.localTree.lcaBlockIdAndHeight(a, b)

func canonicalTip*(cs: ConsensusState): Tip =
  cs.canonicalTip

func latestImmutableId*(cs: ConsensusState): BlockId =
  cs.latestImmutableId

func forkChoiceRule*(cs: ConsensusState): ForkChoiceRule =
  cs.forkChoiceRule

func securityParam(cs: ConsensusState): uint64 =
  cs.securityParam

func latestImmutableHeight(cs: ConsensusState): uint64 =
  cs.localTree.blockHeight(cs.latestImmutableId).valueOr:
    raiseAssert "ConsensusState invariant violated: LIB not in local tree"

func latestImmutableSlot*(cs: ConsensusState): SlotNumber =
  let hdr = cs.localTree.fetchHeader(cs.latestImmutableId).valueOr:
    raiseAssert "ConsensusState invariant violated: LIB not in local tree"
  hdr.slot

# https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/cryptarchia-v1-protocol.md#block-validation
func canDescendFromImmutable*(cs: ConsensusState, header: Header): bool =
  ## Validates whether a block header can descend from the latest immutable block:
  ## - For known parents: candidate height > immutable height and ancestry path to LIB.
  ##   Fast paths:
  ##   - Parent is canonical tip: by invariant, the canonical tip always descends from LIB
  ##     and satisfies canonicalTip.height >= latestImmutableHeight().
  ##   - Parent is LIB itself: trivially descends from LIB.
  ## - For unknown parents (orphans): slot feasibility (header.slot > immutableSlot).
  if header.parentBlock.isZero:
    return false
  if header.slot <= cs.latestImmutableSlot():
    return false
  if cs.localTree.hasBlock(header.parentBlock):
    if header.parentBlock == cs.canonicalTip.tip or header.parentBlock == cs.latestImmutableId:
      return true
    let parentHeight = cs.localTree.blockHeight(header.parentBlock).valueOr:
      raiseAssert "ConsensusState invariant violated: parent in tree but blockHeight missing"
    if parentHeight + 1'u64 <= cs.latestImmutableHeight():
      return false
    return cs.localTree.isAncestor(ancestor = cs.latestImmutableId, descendant = header.parentBlock)
  true

func init*(
    T: type ConsensusState,
    genesisBlock: ValidBlock,
    securityParam: uint64,
    densitySlotWindow: uint64,
    forkChoiceRule: ForkChoiceRule,
): ConsensusState =
  let gid = blockId(genesisBlock.header)
  ConsensusState(
    localTree: LocalTree.init(genesisBlock),
    forkChoiceRule: forkChoiceRule,
    securityParam: securityParam,
    densitySlotWindow: densitySlotWindow,
    cache: ForkChoiceDensityCache.init(),
    canonicalTip: Tip(
      tip: gid,
      slot: genesisBlock.header.slot,
      height: 0'u64,
    ),
    latestImmutableId: gid,
  )

proc switchToOnline*(cs: ConsensusState) =
  cs.forkChoiceRule = ForkChoiceRule.Online

# https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/cryptarchia-v1-protocol.md#immutable-blocks
proc tryUpdateLib*(cs: ConsensusState): seq[BlockId] =
  let tipHeight = cs.canonicalTip.height
  if tipHeight >= cs.securityParam:
    let
      immHeight = tipHeight - cs.securityParam
      oldImmHeight = cs.latestImmutableHeight()
    if immHeight > oldImmHeight:
      let newImmId = cs.localTree.ancestorAtHeight(cs.canonicalTip.tip, immHeight).valueOr:
        raiseAssert "ConsensusState invariant violated: ancestor at immHeight not found on canonical tip branch"
      cs.latestImmutableId = newImmId
      return cs.localTree.pruneForks(newImmId, oldImmHeight, tipHeight)
  @[]

proc densityOf(
    cs: ConsensusState,
    tipId: BlockId,
    lcaSlot: SlotNumber,
    lcaHeight: uint64,
): uint64 =
  let key = DensityCacheKey(tipId: tipId, lcaSlot: lcaSlot)
  cs.cache.lru.get(key).valueOr:
    let d = cs.localTree.countChainDensity(tipId, lcaSlot, lcaHeight, cs.densitySlotWindow)
    cs.cache.lru.put(key, d)
    d

proc preferCandidate(
    cs: ConsensusState,
    currentTipId, candidateId: BlockId,
): bool =
  ## Evaluates whether candidateId should replace currentTipId as the active canonical tip
  ## under the specified ConsensusState configuration.
  ##
  ## Invariant:
  ## 1. Candidate must not be zero or identical to current tip.
  ## 2. When divergence depth <= securityParam (shallow fork), longest chain wins.
  ## 3. When divergence depth > securityParam (deep fork):
  ##    - Online mode: strictly rejects the deep fork (returns false).
  ##    - Bootstrap mode: compares primary block densities in the window (lcaSlot, lcaSlot + densitySlotWindow].
  ## 4. On tie (equal height for shallow, equal density for deep), current tip is preserved (returns false).
  if candidateId.isZero or currentTipId == candidateId:
    return false

  let (lcaId, lcaHeight) = cs.localTree.lcaBlockIdAndHeight(currentTipId, candidateId).valueOr:
    return false

  let curTipHeight = cs.localTree.blockHeight(currentTipId).valueOr:
    return false
  let candHeight = cs.localTree.blockHeight(candidateId).valueOr:
    return false

  let lcaHeader = cs.localTree.fetchHeader(lcaId).valueOr:
    return false

  let divergenceDepth = curTipHeight - lcaHeight

  if divergenceDepth <= cs.securityParam:
    # Shallow fork: strictly longer chain wins
    return candHeight > curTipHeight

  # Deep fork (divergenceDepth > securityParam)
  case cs.forkChoiceRule
  of ForkChoiceRule.Online:
    # Online rule forbids reorganizations beyond finality depth k
    return false
  of ForkChoiceRule.Bootstrap:
    # Bootstrap rule compares chain densities in the slot window s_gen immediately following LCA
    let candDensity = cs.densityOf(candidateId, lcaHeader.slot, lcaHeight)
    # Early shortcut: if candidate has zero density in the window, it cannot beat incumbent (avoids looking up curDensity)
    if candDensity == 0:
      return false
    let curDensity = cs.densityOf(currentTipId, lcaHeader.slot, lcaHeight)
    return candDensity > curDensity

proc tryUpdateTip(
    cs: ConsensusState,
    candidateId: BlockId,
) =
  ## Updates the canonical tip if candidateId is strictly preferred over the current tip
  ## according to the active fork choice rule (Online: Ouroboros Praos; Bootstrap: Ouroboros Genesis).
  if cs.preferCandidate(cs.canonicalTip.tip, candidateId):
    let hdr = cs.localTree.fetchHeader(candidateId).valueOr:
      raiseAssert "ConsensusState invariant violated: preferCandidate succeeded but candidate header missing"
    let height = cs.localTree.blockHeight(candidateId).valueOr:
      raiseAssert "ConsensusState invariant violated: preferCandidate succeeded but candidate height missing"
    cs.canonicalTip = Tip(
      tip: candidateId,
      slot: hdr.slot,
      height: height,
    )

proc addBlockAndTryUpdateTip*(cs: ConsensusState, blk: ValidBlock): bool =
  ## Inserts a block into the local tree and attempts to update the canonical tip.
  let id = blockId(blk.header)
  if not cs.localTree.addBlockToTree(blk):
    return false
  cs.tryUpdateTip(id)
  true

when defined(unittest) or defined(test):
  func localTree*(cs: ConsensusState): LocalTree =
    cs.localTree

{.pop.}
