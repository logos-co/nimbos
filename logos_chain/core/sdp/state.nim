# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP-specific state/domain types layered on top of Bedrock primitives.
## Spec: [v1.5.0 Mantle](https://nomos-tech.notion.site/1-5-0-Mantle-33d261aa09df8051b0d0cd4d5ddade85)

{.push raises: [], gcsafe.}

import std/sets
import libp2p/multiaddress
import ../mantle/primitives


type
  LockedNote* = object
    declarations*: HashSet[DeclarationId]
    lockedUntil*: BlockNumber

  MinStake* = object
    stakeThreshold*: uint64
    timestamp*: BlockNumber

  ServiceParameters* = object
    lockPeriod*: uint64
    inactivityPeriod*: uint64
    retentionPeriod*: uint64
    timestamp*: BlockNumber

  DeclarationInfo* = object
    service*: ServiceType
    locators*: seq[Locator]
    providerId*: Ed25519PublicKey
    zkId*: ZkPublicKey
    lockedNoteId*: NoteId
    created*: BlockNumber
    active*: BlockNumber
    withdrawn*: BlockNumber
    nonce*: Nonce


func validateLocator*(locator: Locator) =
  doAssert locator.data().buffer.len <= MaxLocatorMultiaddrBytes

{.pop.}
