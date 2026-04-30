# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Spec: [v1.4 Mantle](https://nomos-tech.notion.site/v1-4-Mantle-335261aa09df8065a38acff4b25aee82)

{.push raises: [], gcsafe.}

import ./primitives
import ./proofs
import ./opcodes
export primitives, proofs, opcodes

# ---------------------------------------------------------------------------
# Transfer (``OpTransfer``)
# ---------------------------------------------------------------------------

type
  TransferPayload* = object
    inputs*: Inputs
    outputs*: Outputs

# ---------------------------------------------------------------------------
# Channel inscribe (``OpChannelInscribe``)
# ---------------------------------------------------------------------------

type
  ChannelInscribePayload* = object
    channelId*: ChannelId
    inscription*: Inscription
    parent*: Parent
    signer*: Signer

# ---------------------------------------------------------------------------
# Channel deposit / withdraw (``OpChannelDeposit``, ``OpChannelWithdraw``)
# ---------------------------------------------------------------------------
# Channel deposit (``OpChannelDeposit``)
# ---------------------------------------------------------------------------

type
  ## ``ChannelId`` * ``Inputs`` * ``Metadata``.
  ## ``Inputs`` is the list of consumed ``NoteId`` values.
  ChannelDepositPayload* = object
    channel*: ChannelId
    inputs*: seq[NoteId]
    metadata*: Metadata

# ---------------------------------------------------------------------------
# Channel withdraw (``OpChannelWithdraw``)
# ---------------------------------------------------------------------------

type
  ## ``ChannelId`` * ``Outputs`` * ``OpIdNonce``.
  ChannelWithdrawPayload* = object
    channel*: ChannelId
    outputs*: seq[Note]
    opIdNonce*: uint32

# ---------------------------------------------------------------------------
# SDP (``OpSdpDeclare``, ``OpSdpWithdraw``, ``OpSdpActive``)
# ---------------------------------------------------------------------------

type
  ## ``ServiceType`` * ``Locator`` list * ``ProviderId`` * ``ZkId`` * ``LockedNoteId`` (``OpSdpDeclare``).
  ## Well-formed: ``locators.len <= MaxSdpLocators`` and each ``Locator`` <= **``MaxLocatorMultiaddrBytes``** bytes.
  SdpDeclarePayload* = object
    serviceType*: ServiceType
    locators*: seq[Locator]
    providerId*: ProviderId
    zkId*: ZkId
    lockedNoteId*: NoteId

  ## ``DeclarationId`` * ``Nonce`` * ``LockedNoteId`` (``OpSdpWithdraw``).
  SdpWithdrawPayload* = object
    declarationId*: DeclarationId
    lockedNoteId*: NoteId
    nonce*: Nonce

  ## ``DeclarationId`` * ``Nonce`` * ``Metadata`` (``OpSdpActive``).
  SdpActivePayload* = object
    declarationId*: DeclarationId
    nonce*: Nonce
    metadata*: Metadata

# ---------------------------------------------------------------------------
# Leader claim (``OpLeaderClaim``)
# ---------------------------------------------------------------------------

type
  ## ``RewardsRoot`` * ``VoucherNullifier`` * ``PublicKey`` (``OpLeaderClaim``).
  ## ``PublicKey`` = ``ZkPublicKey``.
  LeaderClaimPayload* = object
    rewardsRoot*: RewardsRoot
    voucherNullifier*: VoucherNullifier
    publicKey*: PublicKey

# ---------------------------------------------------------------------------
# Channel config (``OpChannelConfig``)
# ---------------------------------------------------------------------------

type
  ChannelConfigPayload* = object
    channel*: ChannelId
    keys*: seq[Ed25519PublicKey]
    postingTimeframe*: PostingTimeframe
    postingTimeout*: PostingTimeout
    configurationThreshold*: ConfigurationThreshold
    withdrawThreshold*: WithdrawThreshold

# ---------------------------------------------------------------------------
# Wire sum **``OpPayload``**
# ---------------------------------------------------------------------------

type
  OpPayloadTag* = enum
    Transfer
    ChannelInscribe
    ChannelDeposit
    ChannelWithdraw
    SdpDeclare
    SdpWithdraw
    SdpActive
    LeaderClaim
    ChannelConfig

  OpPayload* = object
    case kind*: OpPayloadTag
    of Transfer: transfer*: TransferPayload
    of ChannelInscribe: channelInscribe*: ChannelInscribePayload
    of ChannelDeposit: channelDeposit*: ChannelDepositPayload
    of ChannelWithdraw: channelWithdraw*: ChannelWithdrawPayload
    of SdpDeclare: sdpDeclare*: SdpDeclarePayload
    of SdpWithdraw: sdpWithdraw*: SdpWithdrawPayload
    of SdpActive: sdpActive*: SdpActivePayload
    of LeaderClaim: leaderClaim*: LeaderClaimPayload
    of ChannelConfig: channelConfig*: ChannelConfigPayload

  ## In-memory operation envelope.
  Op* = object
    opcode*: Opcode
    payload*: OpPayload

# ---------------------------------------------------------------------------
# Op constructors
# ---------------------------------------------------------------------------

func createTransferOp*(payload: TransferPayload): Op =
  Op(opcode: OpTransfer, payload: OpPayload(kind: Transfer, transfer: payload))

func createChannelInscribeOp*(payload: ChannelInscribePayload): Op =
  Op(
    opcode: OpChannelInscribe,
    payload: OpPayload(kind: ChannelInscribe, channelInscribe: payload),
  )

func createChannelDepositOp*(payload: ChannelDepositPayload): Op =
  Op(
    opcode: OpChannelDeposit,
    payload: OpPayload(kind: ChannelDeposit, channelDeposit: payload),
  )

func createChannelWithdrawOp*(payload: ChannelWithdrawPayload): Op =
  Op(
    opcode: OpChannelWithdraw,
    payload: OpPayload(kind: ChannelWithdraw, channelWithdraw: payload),
  )

func createSdpDeclareOp*(payload: SdpDeclarePayload): Op =
  Op(opcode: OpSdpDeclare, payload: OpPayload(kind: SdpDeclare, sdpDeclare: payload))

func createSdpWithdrawOp*(payload: SdpWithdrawPayload): Op =
  Op(
    opcode: OpSdpWithdraw,
    payload: OpPayload(kind: SdpWithdraw, sdpWithdraw: payload),
  )

func createSdpActiveOp*(payload: SdpActivePayload): Op =
  Op(opcode: OpSdpActive, payload: OpPayload(kind: SdpActive, sdpActive: payload))

func createLeaderClaimOp*(payload: LeaderClaimPayload): Op =
  Op(opcode: OpLeaderClaim, payload: OpPayload(kind: LeaderClaim, leaderClaim: payload))

func createChannelConfigOp*(payload: ChannelConfigPayload): Op =
  Op(
    opcode: OpChannelConfig,
    payload: OpPayload(kind: ChannelConfig, channelConfig: payload),
  )

# ---------------------------------------------------------------------------
# Opcode mapping
# ---------------------------------------------------------------------------

func opPayloadToOpcode*(p: OpPayload): Opcode =
  case p.kind
  of Transfer: OpTransfer
  of ChannelInscribe: OpChannelInscribe
  of ChannelDeposit: OpChannelDeposit
  of ChannelWithdraw: OpChannelWithdraw
  of SdpDeclare: OpSdpDeclare
  of SdpWithdraw: OpSdpWithdraw
  of SdpActive: OpSdpActive
  of LeaderClaim: OpLeaderClaim
  of ChannelConfig: OpChannelConfig

func expectedOpProofKindForOpcode*(opcode: Opcode): OpProofKind =
  case opcode
  of OpTransfer: opfTransfer
  of OpChannelInscribe: opfChannelInscribe
  of OpChannelDeposit: opfChannelDeposit
  of OpChannelWithdraw: opfChannelWithdraw
  of OpSdpDeclare: opfSdpDeclare
  of OpSdpWithdraw: opfSdpWithdraw
  of OpSdpActive: opfSdpActive
  of OpLeaderClaim: opfLeaderClaim
  of OpChannelConfig: opfChannelConfig
  else:
    doAssert false, "unknown opcode for OpProof expectation: " & $opcode
    default(OpProofKind)

func defaultOpForOpcode*(opcode: Opcode): Op =
  ## Canonical default/empty op payload for a given opcode.
  case opcode
  of OpTransfer:
    createTransferOp(TransferPayload(
      inputs: Inputs(noteIds: @[]),
      outputs: Outputs(notes: @[]),
    ))
  of OpChannelInscribe:
    createChannelInscribeOp(ChannelInscribePayload(
      channelId: default(ChannelId),
      inscription: @[],
      parent: default(Parent),
      signer: default(Signer),
    ))
  of OpChannelDeposit:
    createChannelDepositOp(ChannelDepositPayload(
      channel: default(ChannelId),
      inputs: @[],
      metadata: @[],
    ))
  of OpChannelWithdraw:
    createChannelWithdrawOp(ChannelWithdrawPayload(
      channel: default(ChannelId),
      outputs: @[],
      opIdNonce: 0'u32,
    ))
  of OpSdpDeclare:
    createSdpDeclareOp(SdpDeclarePayload(
      serviceType: default(ServiceType),
      locators: @[],
      providerId: default(ProviderId),
      zkId: default(ZkId),
      lockedNoteId: default(LockedNoteId),
    ))
  of OpSdpWithdraw:
    createSdpWithdrawOp(SdpWithdrawPayload(
      declarationId: default(DeclarationId),
      nonce: default(Nonce),
      lockedNoteId: default(LockedNoteId),
    ))
  of OpSdpActive:
    createSdpActiveOp(SdpActivePayload(
      declarationId: default(DeclarationId),
      nonce: default(Nonce),
      metadata: @[],
    ))
  of OpLeaderClaim:
    createLeaderClaimOp(LeaderClaimPayload(
      rewardsRoot: default(RewardsRoot),
      voucherNullifier: default(VoucherNullifier),
      publicKey: default(ZkPublicKey),
    ))
  of OpChannelConfig:
    createChannelConfigOp(ChannelConfigPayload(
      channel: default(ChannelId),
      keys: @[],
      postingTimeframe: default(PostingTimeframe),
      postingTimeout: default(PostingTimeout),
      configurationThreshold: default(ConfigurationThreshold),
      withdrawThreshold: default(WithdrawThreshold),
    ))
  else:
    doAssert false, "unknown opcode for default op: " & $opcode
    default(Op)

{.pop.}
