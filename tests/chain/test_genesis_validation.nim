# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Genesis transaction validation: the stateless pass, the parameter
## inscription decode and the genesis ledger state.

# `gcsafe` deliberately omitted: `parseDeploymentSettings` (YAML) is not
# GC-safe, matching `tests/chain/test_chain_wiring.nim`.
{.push raises: [].}
{.used.}

import
  std/[os, sequtils, strutils],
  unittest2,
  results,
  stew/[byteutils, endians2, io2],
  libp2p/crypto/ed25519/ed25519,
  libp2p/multiaddress,
  ../../logos_chain/chain/chain,
  ../../logos_chain/core/crypto/types,
  ../../logos_chain/core/mantle/tx_validation,
  ../../logos_chain/deployment/deployment_settings,
  ../core/mantle/test_helpers,
  ../ledger/sdp/test_helpers,
  ../ledger/test_helpers,
  ../testutil

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  deploymentSettingsPath = testsDir / "../../config/deployment-settings.yaml"
  # Worked example per `bedrock-genesis-block.md` §Cryptarchia Parameters:
  # chain id "nomos-mainnet", genesis time 2026-01-05T19:20:35+00:00 (u32-le),
  # little-endian nonce below the BN254 order.
  SpecNonceHex =
    "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567800"
  SpecInscription = hexToSeqByte(
    "0d6e6f6d6f732d6d61696e6e6574030f5c69" & SpecNonceHex)

func withOps(ops: openArray[Op]): SignedMantleTx =
  ## `ops` with a placeholder proof of the right kind for each.
  SignedMantleTx(
    tx: MantleTx(ops: @ops),
    opProofs: ops.mapIt(defaultOpProofForOpcode(it.opcode)))

proc declareOn(
    noteId: NoteId, zkId: ZkPublicKey, providerSeed: byte = 1
): DeclarationMessage =
  DeclarationMessage(
    serviceType: ServiceType.bn, locators: @[mkLocator(30303)],
    providerId: mkProvider(providerSeed), lockedNoteId: noteId, zkId: zkId)

func inscriptionOf(tx: ValidGenesisMantleTx): ChannelInscribePayload =
  tx.tx.ops[1].payload.channelInscribe

func inscriptionWithChainId(chainId: openArray[byte]): seq[byte] =
  ## Parameter inscription with `chainId` bytes, zero time and zero nonce.
  @[byte chainId.len] & @chainId & @(toBytesLE(0'u32)) &
    @(encodeFieldElement(default(FieldElement)))

func withInscription(inscribe: ChannelInscribePayload): ValidGenesisMantleTx =
  ## Genesis transaction whose parameter inscription is `inscribe`; the
  ## cast skips stage 1 so the later stages see the payload unchanged.
  var tx = SignedMantleTx(testGenesisTx())
  tx.tx.ops[1].payload.channelInscribe = inscribe
  ValidGenesisMantleTx(tx)

proc genesisState(
    tx: ValidGenesisMantleTx, cfg = testLedgerConfig
): Result[LedgerState, LedgerError] =
  LedgerState.fromGenesis(tx, default(FieldElement), testSdpRegistry(), cfg)

suite "chain/genesis validation: stage 1 (stateless)":
  test "accepts Transfer + Inscribe":
    check validateGenesisTxStateless(SignedMantleTx(testGenesisTx())).isOk

  test "accepts N declarations":
    let
      declarations = [1'u8, 2, 3].mapIt(declareOn(fe(it), mkZkPubKey(it), it))
      tx = SignedMantleTx(testGenesisTx(declarations = declarations))
    check:
      validateGenesisTxStateless(tx).isOk
      tx.tx.ops.len == 5

  test "rejects empty ops":
    check validateGenesisTxStateless(withOps([])).error ==
      StatelessLedgerError.GenesisShape

  test "rejects a lone Transfer":
    let ops = SignedMantleTx(testGenesisTx()).tx.ops
    check validateGenesisTxStateless(withOps([ops[0]])).error ==
      StatelessLedgerError.GenesisShape

  test "rejects an Inscribe first":
    let ops = SignedMantleTx(testGenesisTx()).tx.ops
    check validateGenesisTxStateless(withOps([ops[1], ops[0]])).error ==
      StatelessLedgerError.GenesisShape

  test "rejects two Transfers":
    let ops = SignedMantleTx(testGenesisTx()).tx.ops
    check validateGenesisTxStateless(withOps([ops[0], ops[0]])).error ==
      StatelessLedgerError.GenesisShape

  test "rejects a Transfer after a Declare":
    let ops = SignedMantleTx(
      testGenesisTx(declarations = [declareOn(fe(1), mkZkPubKey(1))])).tx.ops
    check validateGenesisTxStateless(
      withOps([ops[0], ops[1], ops[2], ops[0]])).error ==
      StatelessLedgerError.GenesisShape

  test "rejects any other opcode":
    let ops = SignedMantleTx(testGenesisTx()).tx.ops
    for extra in [
        createSdpWithdrawOp(WithdrawMessage()),
        createChannelConfigOp(ChannelConfigPayload()),
        createLeaderClaimOp(LeaderClaimPayload())]:
      check validateGenesisTxStateless(withOps([ops[0], ops[1], extra])).error ==
        StatelessLedgerError.GenesisShape

  test "accepts 255 ops":
    let declarations = (1 .. MantleMaxOps - 2).mapIt(
      declareOn(fe(uint64 it), mkZkPubKey(byte it), byte it))
    check SignedMantleTx(testGenesisTx(declarations = declarations)).tx.ops.len ==
      MantleMaxOps

  test "rejects 256 ops":
    let
      ops = SignedMantleTx(testGenesisTx()).tx.ops
      extra = (1 .. MantleMaxOps - 1).mapIt(
        createSdpDeclareOp(declareOn(fe(uint64 it), mkZkPubKey(byte it), byte it)))
    check validateGenesisTxStateless(withOps(ops & extra)).error ==
      StatelessLedgerError.TooManyOps

  test "accepts 255 outputs":
    let outputs = (1 .. int(high(byte))).mapIt(Note(value: 1, zkPublicKey: testZkPk()))
    check SignedMantleTx(testGenesisTx(outputs = outputs)).tx.ops[0]
      .payload.transfer.outputs.notes.len == int(high(byte))

  test "rejects 256 outputs":
    var tx = SignedMantleTx(testGenesisTx())
    tx.tx.ops[0].payload.transfer.outputs.notes =
      (0 .. int(high(byte))).mapIt(Note(value: 1, zkPublicKey: testZkPk()))
    check validateGenesisTxStateless(tx).error == StatelessLedgerError.TooManyOutputs

  test "rejects an inscription on a non-null channel":
    var tx = SignedMantleTx(testGenesisTx())
    tx.tx.ops[1].payload.channelInscribe.channelId[0] = 1
    check validateGenesisTxStateless(tx).error ==
      StatelessLedgerError.GenesisInscription

  test "rejects a non-zero signer":
    var
      raw: array[32, byte]
      tx = SignedMantleTx(testGenesisTx())
    raw[0] = 1
    check tx.tx.ops[1].payload.channelInscribe.signer.init(raw)
    check validateGenesisTxStateless(tx).error ==
      StatelessLedgerError.GenesisInscription

  test "rejects an opcode that disagrees with its payload":
    var tx = SignedMantleTx(testGenesisTx())
    tx.tx.ops[1].opcode = OpTransfer
    check validateGenesisTxStateless(tx).error == StatelessLedgerError.UnsupportedOp

  test "rejects a proof count that differs from the op count":
    var tx = SignedMantleTx(testGenesisTx())
    tx.opProofs.setLen(1)
    check validateGenesisTxStateless(tx).error == StatelessLedgerError.InvalidProof

  test "rejects a wrong proof kind on each op":
    for i in 0 .. 2:
      var tx = SignedMantleTx(
        testGenesisTx(declarations = [declareOn(fe(1), mkZkPubKey(1))]))
      tx.opProofs[i] = defaultOpProofForOpcode(
        if i == 0: OpChannelInscribe else: OpTransfer)
      check validateGenesisTxStateless(tx).error == StatelessLedgerError.InvalidProof

  test "rejects a Transfer with an input":
    var tx = SignedMantleTx(testGenesisTx())
    tx.tx.ops[0].payload.transfer.inputs.noteIds = @[fe(1)]
    check validateGenesisTxStateless(tx).error == StatelessLedgerError.GenesisInputs

  test "rejects a zero-value output":
    var tx = SignedMantleTx(testGenesisTx())
    tx.tx.ops[0].payload.transfer.outputs.notes[0].value = 0
    check validateGenesisTxStateless(tx).error == StatelessLedgerError.ZeroValueNote

  test "rejects zero locators":
    var tx = SignedMantleTx(
      testGenesisTx(declarations = [declareOn(fe(1), mkZkPubKey(1))]))
    tx.tx.ops[2].payload.sdpDeclare.locators = @[]
    check validateGenesisTxStateless(tx).error == StatelessLedgerError.EmptyLocators

  test "rejects nine locators":
    var tx = SignedMantleTx(
      testGenesisTx(declarations = [declareOn(fe(1), mkZkPubKey(1))]))
    tx.tx.ops[2].payload.sdpDeclare.locators =
      (0 .. MaxSdpLocators).mapIt(mkLocator(30303))
    check validateGenesisTxStateless(tx).error == StatelessLedgerError.TooManyLocators

  test "rejects an invalid locator":
    var tx = SignedMantleTx(
      testGenesisTx(declarations = [declareOn(fe(1), mkZkPubKey(1))]))
    # Exceeds MaxLocatorMultiaddrBytes.
    tx.tx.ops[2].payload.sdpDeclare.locators =
      @[MultiAddress.init("/dns4/" & repeat('a', 350) & "/tcp/1234").get]
    check validateGenesisTxStateless(tx).error == StatelessLedgerError.InvalidLocator

suite "chain/genesis validation: stage 2 (cryptarchia parameters)":
  test "decodes what the test helper encodes":
    let
      nonce = fe(42)
      param = cryptarchiaParameter(
        testGenesisTx(chainId = "x", genesisTime = 7, epochNonce = nonce)
      ).expect("valid inscription")
    check:
      param.chainId == "x"
      param.genesisTime == 7
      param.epochNonce == nonce

  test "decodes the spec worked example":
    var inscribe = inscriptionOf(testGenesisTx())
    inscribe.inscription = SpecInscription
    let param = cryptarchiaParameter(withInscription(inscribe)).expect("valid inscription")
    check:
      param.chainId == "nomos-mainnet"
      param.genesisTime == 0x695c0f03'u64
      param.epochNonce ==
        frFromBytesLE(hexToSeqByte(SpecNonceHex)).expect("below order")

  test "rejects trailing bytes":
    var inscribe = inscriptionOf(testGenesisTx())
    inscribe.inscription.add 0
    check cryptarchiaParameter(withInscription(inscribe)).isErr

  test "rejects a truncated inscription":
    var inscribe = inscriptionOf(testGenesisTx())
    inscribe.inscription.setLen(inscribe.inscription.len - 1)
    check cryptarchiaParameter(withInscription(inscribe)).isErr

  test "rejects a chain-id length that disagrees with the payload":
    var inscribe = inscriptionOf(testGenesisTx())
    inscribe.inscription[0] = 0x0c # claims 12 bytes; payload has 4
    check cryptarchiaParameter(withInscription(inscribe)).isErr

  test "rejects a chain id of 0 bytes":
    var inscribe = inscriptionOf(testGenesisTx())
    inscribe.inscription = inscriptionWithChainId([])
    check cryptarchiaParameter(withInscription(inscribe)).isErr

  test "decodes a multibyte UTF-8 chain id":
    let param = cryptarchiaParameter(testGenesisTx(chainId = "ü€😀"))
      .expect("valid inscription")
    check param.chainId == "ü€😀"

  test "rejects a chain id that is not valid UTF-8":
    for bad in [
        @[byte 0xff],                   # not a lead byte
        @[byte 0xe0, 0x80, 0x80],       # overlong 3-byte form
        @[byte 0xed, 0xa0, 0x80],       # UTF-16 surrogate
        @[byte 0xf4, 0x90, 0x80, 0x80], # above U+10FFFF
        @[byte 0xe2, 0x82]]:            # truncated sequence
      var inscribe = inscriptionOf(testGenesisTx())
      inscribe.inscription = inscriptionWithChainId(bad)
      check cryptarchiaParameter(withInscription(inscribe)).isErr

  test "rejects an epoch nonce at or above the BN254 order":
    var inscribe = inscriptionOf(testGenesisTx())
    inscribe.inscription[^1] = 0x90 # little-endian top byte 0x90 > the order's 0x30
    check cryptarchiaParameter(withInscription(inscribe)).isErr

suite "chain/genesis validation: stage 3 (ledger state)":
  test "accepts the devnet genesis":
    let
      dsText = readAllChars(deploymentSettingsPath).valueOr:
        check false
        return
      ds = parseDeploymentSettings(dsText).valueOr:
        check false
        return
      valid = validateGenesisTxStateless(
          ds.cryptarchia.genesisState.signedMantleTx).valueOr:
        check false
        return
      param = cryptarchiaParameter(valid).valueOr:
        check false
        return
      cfg = ledgerConfig(ds)
      state = LedgerState.fromGenesis(
        valid, param.epochNonce,
        SdpRegistry.init(
          ds.cryptarchia.sdpConfig,
          blendRewardsParams(ds, cfg.epochSchedule.epochLength)), cfg).valueOr:
        check false
        return
    check state.sdp.state.declarations.len == 1
    for info in state.sdp.state.declarations.values:
      check state.latestUtxos.get(info.lockedNoteId).isSome

  test "rejects an inscription whose parent is not the root message":
    var inscribe = inscriptionOf(testGenesisTx())
    inscribe.parent[0] = 1
    check genesisState(withInscription(inscribe)).error == LedgerError.InvalidParent

  test "rejects a stake sum that overflows uint64":
    let tx = testGenesisTx(outputs = [
      Note(value: uint64.high, zkPublicKey: mkZkPubKey(1)),
      Note(value: 1, zkPublicKey: mkZkPubKey(2))])
    check genesisState(tx).error == LedgerError.TotalStakeOverflow

  test "rejects a declaration on a note the Transfer did not create":
    let tx = testGenesisTx(declarations = [declareOn(fe(99), testZkPk())])
    check genesisState(tx).error == LedgerError.LockedNoteNotFound

  test "rejects a declaration below the minimum stake":
    let
      outputs = [Note(value: 50, zkPublicKey: testZkPk())]
      noteId = genesisNoteId(testGenesisTx(outputs = outputs), 0)
      tx = testGenesisTx(
        outputs = outputs, declarations = [declareOn(noteId, testZkPk())])
    check genesisState(tx).error == LedgerError.InsufficientStake

  test "rejects the same declaration twice":
    let
      noteId = genesisNoteId(testGenesisTx(), 0)
      declaration = declareOn(noteId, testZkPk())
      tx = testGenesisTx(declarations = [declaration, declaration])
    check genesisState(tx).error == LedgerError.LockedNoteServiceConflict

  test "rejects one declaration on two notes":
    # The declaration id excludes the note, so the second note reaches the
    # duplicate-id check rather than the note-service conflict.
    let
      outputs = [
        Note(value: 1000, zkPublicKey: mkZkPubKey(1)),
        Note(value: 1000, zkPublicKey: mkZkPubKey(2))]
      base = testGenesisTx(outputs = outputs)
      tx = testGenesisTx(outputs = outputs, declarations = [
        declareOn(genesisNoteId(base, 0), mkZkPubKey(1)),
        declareOn(genesisNoteId(base, 1), mkZkPubKey(1))])
    check genesisState(tx).error == LedgerError.DuplicateDeclaration

  test "rejects two declarations with one provider id":
    let
      outputs = [
        Note(value: 1000, zkPublicKey: mkZkPubKey(1)),
        Note(value: 1000, zkPublicKey: mkZkPubKey(2))]
      base = testGenesisTx(outputs = outputs)
      tx = testGenesisTx(outputs = outputs, declarations = [
        declareOn(genesisNoteId(base, 0), mkZkPubKey(1), providerSeed = 1),
        declareOn(genesisNoteId(base, 1), mkZkPubKey(2), providerSeed = 1)])
    check genesisState(tx).error == LedgerError.DuplicateProviderOrZkId

  test "rejects two declarations with one zk id":
    let
      outputs = [
        Note(value: 1000, zkPublicKey: mkZkPubKey(1)),
        Note(value: 1000, zkPublicKey: mkZkPubKey(2))]
      base = testGenesisTx(outputs = outputs)
      tx = testGenesisTx(outputs = outputs, declarations = [
        declareOn(genesisNoteId(base, 0), mkZkPubKey(1), providerSeed = 1),
        declareOn(genesisNoteId(base, 1), mkZkPubKey(1), providerSeed = 2)])
    check genesisState(tx).error == LedgerError.DuplicateProviderOrZkId

  test "stores declarations with created == 0":
    let
      outputs = [
        Note(value: 1000, zkPublicKey: mkZkPubKey(1)),
        Note(value: 1000, zkPublicKey: mkZkPubKey(2))]
      base = testGenesisTx(outputs = outputs)
      tx = testGenesisTx(outputs = outputs, declarations = [
        declareOn(genesisNoteId(base, 0), mkZkPubKey(1), providerSeed = 1),
        declareOn(genesisNoteId(base, 1), mkZkPubKey(2), providerSeed = 2)])
      state = genesisState(tx).expect("genesis state")
    check state.sdp.state.declarations.len == 2
    for info in state.sdp.state.declarations.values:
      check info.created == 0

  test "builds with a faucet note that alone would overflow the stake sum":
    let
      faucetPk = mkZkPubKey(7)
      tx = testGenesisTx(outputs = [
        Note(value: uint64.high, zkPublicKey: faucetPk),
        Note(value: 1000, zkPublicKey: testZkPk())])
    var cfg = testLedgerConfig
    cfg.faucetPk = Opt.some(faucetPk)
    let state = genesisState(tx, cfg).expect("genesis state")
    check:
      state.latestUtxos.len == 2
      state.epochs.activeEpoch.totalStake == 1000

{.pop.}
