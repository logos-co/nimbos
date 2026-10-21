# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Spec: [Cryptarchia Fork Choice Rule](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/fork-choice.md)
## Spec: [Cryptarchia Bootstrapping & Synchronization](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/cryptarchia-v1-bootstr-sync.md)

{.push raises: [], gcsafe.}

import
  intops,
  minilru,
  results

from ../core/crypto/types as crypto_types import isZero
from ../core/mantle/primitives import SlotNumber
from ../core/utils import NonNegativeRatio
from ../core/types import BlockId, Header, Block, Tip, blockId
from ../core/local_tree import
  LocalTree, fetchHeader, blockHeight, lcaBlockIdAndHeight,
  ancestorAtHeight, pruneForks, countChainDensity, isAncestor, hasBlock

export local_tree.countChainDensity

const
  DensityCacheCapacity = 512

type
  ForkChoiceRule* {.pure.} = enum
    Online    ## Ouroboros Praos rule: longest chain for shallow forks (<= k), rejects deep forks (> k)
    Bootstrap ## Ouroboros Genesis rule: longest chain for shallow forks (<= k), density check within s_gen window for deep forks (> k)

  DensityCacheKey = object
    tipId: BlockId
    lcaSlot: SlotNumber

  ForkChoiceDensityCache = ref object
    lru: LruCache[DensityCacheKey, uint64]

  ConsensusState* = ref object
    localTree*: LocalTree
    canonicalTip*: Tip
    latestImmutableId*: BlockId
    forkChoiceRule*: ForkChoiceRule
    securityParam*: uint64
    densitySlotWindow*: uint64
    cache*: ForkChoiceDensityCache

func init(T: type ForkChoiceDensityCache): T =
  T(lru: LruCache[DensityCacheKey, uint64].init(DensityCacheCapacity))

func len*(cache: ForkChoiceDensityCache): int =
  if cache == nil: 0 else: cache.lru.len

func latestImmutableHeight*(cs: ConsensusState): uint64 =
  cs.localTree.blockHeight(cs.latestImmutableId).get(0'u64)

func latestImmutableSlot*(cs: ConsensusState): SlotNumber =
  let hdr = cs.localTree.fetchHeader(cs.latestImmutableId).valueOr:
    return SlotNumber(0)
  hdr.slot

# https://github.com/logos-co/logos-lips/blob/5587d1e5ca2964e38098cd18f81f0fbe19f51fd3/docs/blockchain/raw/cryptarchia-v1-protocol.md#L435-L436
func canDescendFromImmutable*(cs: ConsensusState, header: Header): bool =
  ## Validates whether a block header can descend from the latest immutable block:
  ## - For known parents: candidate height > immutable height and ancestry path to LIB.
  ## - For unknown parents (orphans): slot feasibility (header.slot > immutableSlot).
  if header.parentBlock.isZero:
    return false
  if header.slot <= cs.latestImmutableSlot():
    return false
  if cs.localTree.hasBlock(header.parentBlock):
    let parentHeight = cs.localTree.blockHeight(header.parentBlock).get(0'u64)
    if parentHeight + 1'u64 <= cs.latestImmutableHeight():
      return false
    return cs.localTree.isAncestor(ancestor = cs.latestImmutableId, descendant = header.parentBlock)
  true

func init*(
    T: type ConsensusState,
    genesisBlock: Block,
    securityParam: uint64,
    densitySlotWindow: uint64,
    forkChoiceRule: ForkChoiceRule = ForkChoiceRule.Bootstrap,
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

# https://github.com/logos-co/logos-lips/blob/0ba596cfbd65ea4e9fd16ae572a848fcb43a45d5/docs/blockchain/raw/cryptarchia-v1-protocol.md#L338-L382
proc tryUpdateLib*(cs: ConsensusState): seq[BlockId] =
  let tipHeight = cs.canonicalTip.height
  if tipHeight >= cs.securityParam:
    let immHeight = tipHeight - cs.securityParam
    let oldImmHeight = cs.latestImmutableHeight()
    if immHeight > oldImmHeight:
      let newImmId = cs.localTree.ancestorAtHeight(cs.canonicalTip.tip, immHeight).valueOr:
        return @[]
      cs.latestImmutableId = newImmId
      return cs.localTree.pruneForks(newImmId, oldImmHeight, tipHeight)
  @[]

func getOrComputeDensity*(
    cache: ForkChoiceDensityCache,
    localTree: LocalTree,
    tipId: BlockId,
    lcaSlot: SlotNumber,
    lcaHeight: uint64,
    densitySlotWindow: uint64,
): uint64 =
  if cache == nil:
    return localTree.countChainDensity(tipId, lcaSlot, lcaHeight, densitySlotWindow)
  let key = DensityCacheKey(tipId: tipId, lcaSlot: lcaSlot)
  cache.lru.get(key).valueOr:
    let d = localTree.countChainDensity(tipId, lcaSlot, lcaHeight, densitySlotWindow)
    cache.lru.put(key, d)
    d

func densitySlotWindow*(securityParam: uint64, f: NonNegativeRatio): uint64 =
  ## Returns the density check slot window length s_gen = ⌊k / (4f)⌋ = ⌊(k * f.den) / (4 * f.num)⌋.
  ## For default parameters (k=2160, f=1/30), s_gen = 16200 slots (4h 30m).
  ## Guards against 64-bit integer multiplication overflow and division by zero.
  if f.num == 0 or f.den == 0 or securityParam == 0:
    return 0'u64
  if f.num > uint64.high div 4'u64:
    return 0'u64
  let
    den = 4'u64 * f.num
    (numHi, numLo) = wideningMul(securityParam, f.den)
  if numHi >= den:
    return uint64.high
  let (q, _) = narrowingDiv(numHi, numLo, den)
  q

func preferCandidate*(
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
    let candDensity = cs.cache.getOrComputeDensity(cs.localTree, candidateId, lcaHeader.slot, lcaHeight, cs.densitySlotWindow)
    if candDensity == 0:
      return false
    let curDensity = cs.cache.getOrComputeDensity(cs.localTree, currentTipId, lcaHeader.slot, lcaHeight, cs.densitySlotWindow)
    return candDensity > curDensity

proc tryUpdateTip*(
    cs: ConsensusState,
    candidateId: BlockId,
) =
  if cs.preferCandidate(cs.canonicalTip.tip, candidateId):
    let hdr = cs.localTree.fetchHeader(candidateId).valueOr:
      return
    let height = cs.localTree.blockHeight(candidateId).valueOr:
      return
    cs.canonicalTip = Tip(
      tip: candidateId,
      slot: hdr.slot,
      height: height,
    )

{.pop.}
