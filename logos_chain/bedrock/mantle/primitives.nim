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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
const
  MaxBlockTxs* = 1024
  ## `Ops = OpCount * Op` (wire): one-byte count, then that many ops.
  MantleMaxOps* = 255

  ## SDP locator list limits.
  MaxSdpLocators* = 8
  MaxLocatorMultiaddrBytes* = 329

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

type
  # --- Hash-shaped identifiers (`BYTE32`) ---
  ## `Hash32`/`ZkHash` are defined in `crypto/hashing`.
  MessageId* = Hash32
  ChannelId* = Hash32
  DeclarationId* = Hash32
  Parent* = Hash32
  ## Up to `MaxBlockTxs` tx-hash references.
  References* = array[MaxBlockTxs, Hash32]

  # --- Length-prefixed byte payloads (`UINT32 * BYTE`) ---
  Inscription* = seq[byte]
  Metadata* = seq[byte]

  # --- Block-level scalars ---
  ## Wire `UINT64`.
  SlotNumber* = uint64
  BlockNumber* = uint64
  RewardVoucher* = array[32, byte]

  # --- Wire scalars ---
  ## `UINT64`.
  TokenValue* = uint64
  Value* = uint64
  Amount* = uint64
  Nonce* = uint64

  ## `UINT32`.
  PostingTimeframe* = uint32
  PostingTimeout* = uint32

  ## `UINT16`.
  ConfigurationThreshold* = uint16
  WithdrawThreshold* = uint16

  # --- SDP declare / locators ---
  ## Wire byte: `0 = bn`, `1 = da`.
  ServiceType* = enum
    bn = 0
    da = 1
  ## Wire `UINT16` + payload (multiaddr bytes).
  Locator* = seq[byte]

  # --- Op layout helpers ---
  Opcode* = uint8
  OpCount* = uint8
  HexBytes* = string

  # --- BN254 32-byte field values (LE) ---
  ## FieldElement = 32-byte BN254 field element.
  FieldElement* = array[32, byte]
  NoteId* = FieldElement
  ZkPublicKey* = FieldElement
  ## Transfer note payload.
  Note* = object
    value*: Value
    zkPublicKey*: ZkPublicKey
  ## Transfer input list wrapper.
  Inputs* = object
    noteIds*: seq[NoteId]
  ## Transfer output list wrapper.
  Outputs* = object
    notes*: seq[Note]
  PublicKey* = ZkPublicKey
  RewardsRoot* = FieldElement
  VoucherNullifier* = FieldElement

  # --- Ed25519 identities/signatures ---
  Ed25519PublicKey* = EdPublicKey
  Ed25519Signature* = EdSignature
  ProviderId* = Ed25519PublicKey
  ZkId* = ZkPublicKey
  LockedNoteId* = NoteId
  Signer* = Ed25519PublicKey

  # --- Channel withdraw proof path ---
  ## Signature list metadata (`SignatureCount * ...` wire shape).
  SignatureCount* = uint16
  ChannelKeyIndex* = uint16

{.pop.}
