# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [Cryptarchia Fork Choice Rule v1.1.0](https://github.com/logos-co/logos-lips/blob/663ae35d59d834784dd086cc5f14ec35e8dbecf5/docs/blockchain/raw/fork-choice.md)
## Spec: [Cryptarchia Bootstrapping & Synchronization v1.0.2](https://github.com/logos-co/logos-lips/blob/663ae35d59d834784dd086cc5f14ec35e8dbecf5/docs/blockchain/raw/cryptarchia-v1-bootstr-sync.md)

{.push raises: [], gcsafe.}

import
  minilru,
  results,
  ./local_tree

from std/sets import items
from ../core/crypto/types as crypto_types import isZero
from ../core/types import BlockId, Header, BlockInfo, blockId, BlockNumber, SlotNumber

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

  DensityCache = LruCache[DensityCacheKey, uint64]

  ConsensusState* = ref object
    localTree: LocalTree
    canonicalTip: BlockInfo
    latestImmutable: BlockInfo
    forkChoiceRule: ForkChoiceRule
    securityParam: uint64
    densitySlotWindow: uint64
    densityCache: DensityCache

func genesisId*(cs: ConsensusState): BlockId =
  cs.localTree.genesisId

func hasBlock*(cs: ConsensusState, id: BlockId): bool =
  cs.localTree.hasBlock(id)

func slotOf*(cs: ConsensusState, id: BlockId): Opt[SlotNumber] =
  cs.localTree.slotOf(id)

func parentOf*(cs: ConsensusState, id: BlockId): Opt[BlockId] =
  cs.localTree.parentOf(id)

func blockHeight*(cs: ConsensusState, id: BlockId): Opt[BlockNumber] =
  cs.localTree.blockHeight(id)

func lcaBlockIdAndHeight*(
    cs: ConsensusState, a, b: BlockId,
): Opt[(BlockId, BlockNumber)] =
  cs.localTree.lcaBlockIdAndHeight(a, b)

func canonicalTip*(cs: ConsensusState): BlockInfo =
  cs.canonicalTip

func latestImmutable*(cs: ConsensusState): BlockInfo =
  cs.latestImmutable

func forkChoiceRule*(cs: ConsensusState): ForkChoiceRule =
  cs.forkChoiceRule

# https://github.com/logos-co/logos-lips/blob/663ae35d59d834784dd086cc5f14ec35e8dbecf5/docs/blockchain/raw/cryptarchia-v1-protocol.md#block-header-validation
func canDescendFromImmutable*(cs: ConsensusState, header: Header): bool =
  ## Validates whether a block header can descend from the latest immutable block:
  ## - For known parents: candidate height > immutable height and ancestry path to LIB.
  ##   Fast paths:
  ##   - Parent is canonical tip: by invariant, the canonical tip always descends from LIB
  ##     and satisfies canonicalTip.height >= latestImmutable.height.
  ##   - Parent is LIB itself: trivially descends from LIB.
  ## - For unknown parents (orphans): slot feasibility (header.slot > latestImmutable.slot).
  if header.parentBlock.isZero:
    return false
  if header.slot <= cs.latestImmutable.slot:
    return false
  if header.parentBlock == cs.canonicalTip.id or header.parentBlock == cs.latestImmutable.id:
    return true
  let parentHeight = cs.localTree.blockHeight(header.parentBlock).valueOr:
    return true
  if parentHeight + 1'u64 <= cs.latestImmutable.height:
    return false
  cs.localTree.isAncestor(ancestor = cs.latestImmutable.id, descendant = header.parentBlock)

func init*(
    T: type ConsensusState,
    genesisHeader: Header,
    securityParam: uint64,
    densitySlotWindow: uint64,
    forkChoiceRule: ForkChoiceRule,
): ConsensusState =
  doAssert densitySlotWindow > 0, "ConsensusState invariant violated: densitySlotWindow must be > 0"
  let
    gid = blockId(genesisHeader)
    genesisInfo = BlockInfo(id: gid, slot: genesisHeader.slot, height: 0'u64)
  ConsensusState(
    localTree: LocalTree.init(genesisHeader),
    forkChoiceRule: forkChoiceRule,
    securityParam: securityParam,
    densitySlotWindow: densitySlotWindow,
    densityCache: DensityCache.init(DensityCacheCapacity),
    canonicalTip: genesisInfo,
    latestImmutable: genesisInfo,
  )

proc switchToOnline*(cs: ConsensusState) =
  cs.forkChoiceRule = ForkChoiceRule.Online
  reset(cs.densityCache)

# https://github.com/logos-co/logos-lips/blob/663ae35d59d834784dd086cc5f14ec35e8dbecf5/docs/blockchain/raw/cryptarchia-v1-protocol.md#latest-immutable-block
proc tryUpdateLib*(cs: ConsensusState): seq[BlockId] =
  let tipHeight = cs.canonicalTip.height
  if tipHeight >= cs.securityParam:
    let
      immHeight = tipHeight - cs.securityParam
      oldImmHeight = cs.latestImmutable.height
    if immHeight > oldImmHeight:
      let newImm = cs.localTree.ancestorAtHeight(cs.canonicalTip.id, immHeight).valueOr:
        raiseAssert "ConsensusState invariant violated: ancestor at immHeight not found on canonical tip branch"
      cs.latestImmutable = newImm
      return cs.localTree.pruneForks(newImm.id, oldImmHeight)
  @[]

proc densityOf(
    cs: ConsensusState,
    tipId: BlockId,
    lcaSlot: SlotNumber,
    lcaHeight: uint64,
): uint64 =
  let key = DensityCacheKey(tipId: tipId, lcaSlot: lcaSlot)
  cs.densityCache.get(key).valueOr:
    let d = cs.localTree.countChainDensity(tipId, lcaSlot, lcaHeight, cs.densitySlotWindow)
    cs.densityCache.put(key, d)
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
  doAssert not candidateId.isZero and currentTipId != candidateId,
    "ConsensusState invariant violated: candidate must not be zero or equal to current tip"

  let
    (lcaId, lcaHeight) = cs.localTree.lcaBlockIdAndHeight(currentTipId, candidateId).valueOr:
      raiseAssert "ConsensusState invariant violated: LCA missing for active tree blocks"
    curTipHeight = cs.localTree.blockHeight(currentTipId).valueOr:
      raiseAssert "ConsensusState invariant violated: currentTipId height missing"
    candHeight = cs.localTree.blockHeight(candidateId).valueOr:
      raiseAssert "ConsensusState invariant violated: candidateId height missing"
    divergenceDepth = curTipHeight - lcaHeight

  if divergenceDepth <= cs.securityParam:
    # Shallow fork: strictly longer chain wins
    return candHeight > curTipHeight

  # Deep fork (divergenceDepth > securityParam)
  case cs.forkChoiceRule
  of ForkChoiceRule.Online:
    # Online rule forbids reorganizations beyond finality depth k
    return false
  of ForkChoiceRule.Bootstrap:
    let lcaSlot = cs.localTree.slotOf(lcaId).valueOr:
      raiseAssert "ConsensusState invariant violated: LCA slot missing"
    # Bootstrap rule compares chain densities in the slot window s_gen immediately following LCA
    let candDensity = cs.densityOf(candidateId, lcaSlot, lcaHeight)
    # Early shortcut: if candidate has zero density in the window, it cannot beat incumbent (avoids looking up curDensity)
    if candDensity == 0:
      return false
    let curDensity = cs.densityOf(currentTipId, lcaSlot, lcaHeight)
    return candDensity > curDensity

proc setCanonicalTip(cs: ConsensusState, candidateId: BlockId) =
  cs.canonicalTip = cs.localTree.blockInfo(candidateId).valueOr:
    raiseAssert "ConsensusState invariant violated: selected tip missing"

proc tryUpdateTip(
    cs: ConsensusState,
    candidateId: BlockId,
    parentBlock: BlockId,
) =
  ## Updates the canonical tip according to the active fork choice rule
  ## (Online: Ouroboros Praos; Bootstrap: Ouroboros Genesis).
  # https://github.com/logos-co/logos-lips/blob/663ae35d59d834784dd086cc5f14ec35e8dbecf5/docs/blockchain/raw/cryptarchia-v1-protocol.md#L477
  # Extending the current tip skips fork_choice; in Bootstrap mode, crossing height(LCA) + k -> k + 1
  # via tip extension can make an existing denser tip win under maxvalid-bg (kept spec-literal for now).
  if parentBlock == cs.canonicalTip.id:
    cs.setCanonicalTip(candidateId)
    return

  let startId = cs.canonicalTip.id
  var bestId =
    if cs.preferCandidate(startId, candidateId): candidateId
    else: startId
  if cs.forkChoiceRule == ForkChoiceRule.Bootstrap:
    for tipId in cs.localTree.tips:
      if tipId != bestId and not (tipId == candidateId and bestId == startId) and
          cs.preferCandidate(bestId, tipId):
        bestId = tipId
  if bestId != startId:
    cs.setCanonicalTip(bestId)

proc addHeaderAndTryUpdateTip*(
    cs: ConsensusState, header: Header, id: BlockId
): bool =
  ## Inserts a header (`id == blockId(header)`) into the local tree and updates the canonical tip.
  if not cs.localTree.addHeaderToTree(header, id):
    return false
  cs.tryUpdateTip(id, header.parentBlock)
  true

{.pop.}
