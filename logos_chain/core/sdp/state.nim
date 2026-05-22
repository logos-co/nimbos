# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP-specific state/domain types layered on top of Bedrock primitives.
## Spec: [v1.4 Mantle](https://nomos-tech.notion.site/v1-4-Mantle-335261aa09df8065a38acff4b25aee82)

{.push raises: [], gcsafe.}

import std/sets
import libp2p/multiaddress
import ../mantle/primitives


type
  LockedNote* = object
    declarations*: HashSet[DeclarationId]
    lockedUntil*: BlockNumber

  MinStake* = object
    stakeThreshold*: int
    timestamp*: BlockNumber

  ServiceParameters* = object
    lockPeriod*: int
    inactivityPeriod*: int
    retentionPeriod*: int
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


func validate*(locator: Locator) =
  doAssert locator.len <= MaxLocatorMultiaddrBytes
  var locatorStr = newString(locator.len)
  for i, b in locator:
    locatorStr[i] = char(b)
  doAssert MultiAddress.init(locatorStr).isOk

{.pop.}
