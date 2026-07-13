# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP domain types layered on top of Bedrock mantle primitives.
## Spec: [1.1.0 Service Declaration Protocol](bedrock-service-declaration-protocol.md)
## Spec: [v1.5.0 Mantle](https://nomos-tech.notion.site/1-5-0-Mantle-33d261aa09df8051b0d0cd4d5ddade85)

{.push raises: [], gcsafe.}

import
  results,
  std/sets,
  ../mantle/[primitives, operations],
  ../crypto/hashing,
  ../../utils/hash_trie_map

export primitives, results, hash_trie_map

type
  MinStake* = object
    stakeThreshold*: uint64
    epoch*: EpochNumber

  ServiceParameters* = object
    inactivityPeriod*: uint64
    epoch*: EpochNumber

  DeclarationInfo* = object
    service*: ServiceType
    providerId*: Ed25519PublicKey
    lockedNoteId*: NoteId
    zkId*: ZkPublicKey
    locators*: seq[Locator]
    created*: EpochNumber
    active*: Opt[EpochNumber]
    withdrawAt*: Opt[EpochNumber]
    nonce*: Nonce

  LockedNotes* = HashTrieMap[NoteId, HashSet[DeclarationId]]

func defaultBnServiceParameters*(epoch: EpochNumber = 0): ServiceParameters =
  ServiceParameters(
    inactivityPeriod: 2'u64,
    epoch: epoch,
  )

func declarationId*(declaration: DeclarationMessage): DeclarationId =
  ## ``declaration_id``: wire ServiceType byte, ProviderId 32B, ZkId 32B,
  ## then wire locators (u8 count + u16-prefixed multiaddr bytes), blake2b256.
  var preimage = @[encodeServiceType(declaration.serviceType)]
  preimage.add(encodeProviderId(declaration.providerId))
  preimage.add(encodeZkId(declaration.zkId))
  preimage.add(encodeLocators(declaration.locators))
  blake2b256Hash(preimage)

{.pop.}
