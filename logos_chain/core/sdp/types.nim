# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP domain types layered on top of Bedrock mantle primitives.
## Spec: [1.0.0 Service Declaration Protocol](https://nomos-tech.notion.site/1-0-0-Service-Declaration-Protocol-1fd261aa09df819ca9f8eb2bdfd4ec1d)
## Spec: [v1.5.0 Mantle](https://nomos-tech.notion.site/1-5-0-Mantle-33d261aa09df8051b0d0cd4d5ddade85)

{.push raises: [], gcsafe.}

import
  std/sets,
  ../mantle/[primitives, operations],
  ../crypto/hashing

export primitives

type
  LockedNote* = object
    declarations*: HashSet[DeclarationId]
    lockedUntil*: BlockNumber

  MinStake* = object
    stakeThreshold*: uint64
    timestamp*: BlockNumber

  ServiceParameters* = object
    sessionLength*: uint64
    lockPeriod*: uint64
    inactivityPeriod*: uint64
    retentionPeriod*: uint64
    timestamp*: BlockNumber

  EventType* {.pure.} = enum
    created = 0
    active = 1
    withdrawn = 2

  DeclarationInfo* = object
    service*: ServiceType
    providerId*: Ed25519PublicKey
    lockedNoteId*: NoteId
    zkId*: ZkPublicKey
    locators*: seq[Locator]
    created*: BlockNumber
    active*: BlockNumber
    withdrawn*: BlockNumber
    nonce*: Nonce

func defaultBnServiceParameters*(timestamp: BlockNumber = 0): ServiceParameters =
  ServiceParameters(
    sessionLength: 21600'u64,
    lockPeriod: 1'u64,
    inactivityPeriod: 1'u64,
    retentionPeriod: 1'u64,
    timestamp: timestamp,
  )

func declarationId*(declaration: DeclarationMessage): DeclarationId =
  ## ``declaration_id = Blake2b-256(service || provider_id || zk_id || locators)``.
  var preimage = @[encodeServiceType(declaration.serviceType)]
  preimage.add(encodeProviderId(declaration.providerId))
  preimage.add(encodeZkId(declaration.zkId))
  preimage.add(encodeLocators(declaration.locators))
  blake2b256Hash(preimage)

{.pop.}
