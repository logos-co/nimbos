# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/[os, strutils],
  stew/io2,
  ../../logos_chain/chain/chain,
  ../../logos_chain/deployment/deployment_settings,
  ../testutil

const
  testsDir = currentSourcePath.rsplit({os.DirSep, os.AltSep}, 1)[0]
  deploymentSettingsPath = testsDir / "../../config/deployment-settings.yaml"

suite "chain/genesis":
  test "createGenesisBlock wraps a minimal signed mantle tx":
    let
      tx = MantleTx(ops: @[])
      sm = SignedMantleTx(tx: tx, opProofs: @[])
      h = createGenesisBlock(sm).get.header
      b = createGenesisBlock(sm).get
    check:
      h.bodyRoot == body_root([], [sm]).get
      b.txs.len == 1
      b.header.bedrockVersion == GenesisBedrockVersion
      b.txs[0].tx.ops.len == sm.tx.ops.len
      b.signature == DefaultEd25519Signature

  test "createGenesisBlock returns error on malformed tx":
    var invalidInputs: seq[NoteId]
    for i in 0 .. 255:
      invalidInputs.add(default(NoteId))
    let malformedTx = SignedMantleTx(
      tx: MantleTx(ops: @[createTransferOp(TransferPayload(
        inputs: Inputs(noteIds: invalidInputs), outputs: Outputs(notes: @[])
      ))]),
      opProofs: @[OpProof(kind: opfTransfer, transferProof: default(ZkSigProof))]
    )
    check createGenesisBlock(malformedTx).error == EncodingError.InputsCountExceeded

  test "createGenesisBlock builds expected header/envelope from deployment settings":
    let
      text = readAllChars(deploymentSettingsPath).valueOr:
        fail "could not read deployment settings"
      ds = parseDeploymentSettings(text).valueOr:
        fail "could not parse deployment settings"
    require validateDeploymentSettings(ds).isOk

    let
      gstate = ds.cryptarchia.genesisState
      genesisTx = gstate.signedMantleTx
      testChain = Chain.init(ds).valueOr:
        fail "Chain.init: " & $error
      gb = testChain.genesisBlock

    check:
      gb.txs.len == 1
      gb.txs[0].opProofs.len == genesisTx.opProofs.len
    for i in 0 ..< genesisTx.opProofs.len:
      check gb.txs[0].opProofs[i].kind == genesisTx.opProofs[i].kind
    check:
      gb.txs[0].tx.ops.len == genesisTx.tx.ops.len
      gb.header.bedrockVersion == GenesisBedrockVersion
      gb.header.parentBlock == default(BlockId)
      gb.header.slot == 0'u64
      gb.header.bodyRoot == body_root([], [genesisTx]).get
      gb.header == gstate.header
      gb.signature == gstate.blockSignature

  test "createGenesisBlock from signedMantleTx matches deployment genesisState envelope":
    let
      text = readAllChars(deploymentSettingsPath).valueOr:
        fail "could not read deployment settings"
      ds = parseDeploymentSettings(text).valueOr:
        fail "could not parse deployment settings"
    require validateDeploymentSettings(ds).isOk

    let
      gstate = ds.cryptarchia.genesisState
      fromTx = createGenesisBlock(gstate.signedMantleTx).get
      fromState = initBlock(gstate.header, gstate.blockSignature, [], [gstate.signedMantleTx])

    check:
      fromTx.header == fromState.header
      blockId(fromTx.header) == blockId(fromState.header)
      fromTx.signature == fromState.signature
      fromTx.txs.len == fromState.txs.len
      fromTx.txs.len == 1
      mantleTxHash(fromTx.txs[0].tx).get == mantleTxHash(fromState.txs[0].tx).get
      fromTx.txs[0].opProofs.len == fromState.txs[0].opProofs.len
    for i in 0 ..< fromTx.txs[0].opProofs.len:
      check fromTx.txs[0].opProofs[i].kind == fromState.txs[0].opProofs[i].kind

{.pop.}
