# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [v1.4 Mantle](https://nomos-tech.notion.site/v1-4-Mantle-335261aa09df8065a38acff4b25aee82)

{.push raises: [], gcsafe.}

import ../crypto/hashing
import libp2p/crypto/ed25519/ed25519
export hashing

const
  MaxBlockTxs* = 1024
  MantleMaxOps* = 255
  MaxSdpLocators* = 8
  MaxLocatorMultiaddrBytes* = 329


type
  MessageId* = Hash32
  ChannelId* = Hash32
  DeclarationId* = Hash32
  Parent* = Hash32
  References* = array[MaxBlockTxs, Hash32]

  Inscription* = seq[byte]
  Metadata* = seq[byte]

  SlotNumber* = uint64
  BlockNumber* = uint64
  RewardVoucher* = array[32, byte]

  TokenValue* = uint64
  Value* = uint64
  Amount* = uint64
  Nonce* = uint64

  PostingTimeframe* = uint32
  PostingTimeout* = uint32

  ConfigurationThreshold* = uint16
  WithdrawThreshold* = uint16

  ServiceType* = enum
    bn = 0
    da = 1
  Locator* = seq[byte]

  Opcode* = uint8
  OpCount* = uint8
  HexBytes* = string

  FieldElement* = array[32, byte]
  NoteId* = FieldElement
  ZkPublicKey* = FieldElement
  Note* = object
    value*: Value
    zkPublicKey*: ZkPublicKey
  Inputs* = object
    noteIds*: seq[NoteId]
  Outputs* = object
    notes*: seq[Note]
  PublicKey* = ZkPublicKey
  RewardsRoot* = FieldElement
  VoucherNullifier* = FieldElement

  Ed25519PublicKey* = EdPublicKey
  Ed25519Signature* = EdSignature
  ProviderId* = Ed25519PublicKey
  ZkId* = ZkPublicKey
  LockedNoteId* = NoteId
  Signer* = Ed25519PublicKey

  SignatureCount* = uint16
  ChannelKeyIndex* = uint16

{.pop.}
