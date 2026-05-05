# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[options, strutils],
  results,
  stew/byteutils,
  yaml/dom,
  libp2p/crypto/ed25519/ed25519,
  "../bedrock/block/genesis",
  ./helpers

func parseByteSeqNode(node: YamlNode, path: string): Result[seq[byte], string] =
  if node.kind != ySequence:
    return err("deployment-settings: expected byte sequence at " & path)
  var bytes: seq[byte] = @[]
  for i in 0 ..< node.len:
    let bNode = node[i]
    if bNode.kind != yScalar:
      return err("deployment-settings: expected byte scalar at " & path & "[" & $i & "]")
    let bVal =
      try:
        parseInt(bNode.content)
      except ValueError:
        return err("deployment-settings: expected byte integer at " & path & "[" & $i & "]")
    if bVal < 0 or bVal > 255:
      return err("deployment-settings: byte out of range at " & path & "[" & $i & "]")
    bytes.add(byte(bVal))
  ok(bytes)

func parseHex32Node(node: YamlNode, path: string): Result[array[32, byte], string] =
  if node.kind != yScalar:
    return err("deployment-settings: expected hex scalar at " & path)
  var parsedBytes: array[32, byte]
  try:
    hexToByteArrayStrict(node.content, parsedBytes)
  except ValueError:
    return err("deployment-settings: invalid 32-byte hex at " & path)
  ok(parsedBytes)

func parseUIntNode(node: YamlNode, path: string): Result[uint64, string] =
  if node.kind != yScalar:
    return err("deployment-settings: expected unsigned integer scalar at " & path)
  try:
    ok(parseBiggestUInt(node.content).uint64)
  except ValueError:
    err("deployment-settings: invalid unsigned integer at " & path)

func parseEd25519PublicKeyNode(node: YamlNode, path: string): Result[Ed25519PublicKey, string] =
  if node.kind != yScalar:
    return err("deployment-settings: expected Ed25519 public key scalar at " & path)
  let pk = EdPublicKey.init(node.content).valueOr:
    return err("deployment-settings: invalid Ed25519 public key at " & path)
  ok(pk)

func parseEd25519SignatureNode(node: YamlNode, path: string): Result[Ed25519Signature, string] =
  if node.kind == yScalar:
    let sig = EdSignature.init(node.content).valueOr:
      return err("deployment-settings: invalid Ed25519 signature at " & path)
    return ok(sig)
  let bytes = ? parseByteSeqNode(node, path)
  let sig = EdSignature.init(bytes).valueOr:
    return err("deployment-settings: invalid Ed25519 signature bytes at " & path)
  ok(sig)

func parseZkSigNode(node: YamlNode, path: string): Result[ZkSignature, string] =
  let target =
    if node.kind == yMapping and yamlGetPathNode(node, ["zk_sig"]).isSome:
      yamlGetPathNode(node, ["zk_sig"]).get
    else:
      node
  if target.kind != yMapping:
    return err("deployment-settings: expected zk signature mapping at " & path)
  let paNode = yamlGetPathNode(target, ["pi_a"])
  let pbNode = yamlGetPathNode(target, ["pi_b"])
  let pcNode = yamlGetPathNode(target, ["pi_c"])
  if paNode.isNone or pbNode.isNone or pcNode.isNone:
    return err("deployment-settings: expected pi_a/pi_b/pi_c at " & path)
  let piA = ? parseByteSeqNode(paNode.get, path & ".pi_a")
  let piB = ? parseByteSeqNode(pbNode.get, path & ".pi_b")
  let piC = ? parseByteSeqNode(pcNode.get, path & ".pi_c")
  if piA.len != 32 or piB.len != 64 or piC.len != 32:
    return err("deployment-settings: invalid zk signature component lengths at " & path)
  var zk: ZkSignature
  for i in 0 ..< 32: zk[i] = piA[i]
  for i in 0 ..< 64: zk[32 + i] = piB[i]
  for i in 0 ..< 32: zk[96 + i] = piC[i]
  ok(zk)

func parseGenesisOpPayload(opNode: YamlNode, idx: int, opcode: Opcode): Result[Op, string] =
  let path = "cryptarchia.genesis_state.mantle_tx.ops[" & $idx & "].payload"
  let payloadNode = yamlGetPathNode(opNode, ["payload"])
  if payloadNode.isNone:
    return err("deployment-settings: missing payload at " & path)
  let payload = payloadNode.get
  if payload.kind != yMapping:
    return err("deployment-settings: payload must be a mapping at " & path)
  if payload.len == 0:
    ## Compatibility with older/minimal deployment fixtures that only specify opcode.
    return ok(defaultOpForOpcode(opcode))
  case opcode
  of OpTransfer:
    var noteIds: seq[NoteId] = @[]
    let inputsNode = yamlGetPathNode(payload, ["inputs"])
    if inputsNode.isSome:
      if inputsNode.get.kind != ySequence:
        return err("deployment-settings: transfer inputs must be a sequence at " & path & ".inputs")
      for i in 0 ..< inputsNode.get.len:
        noteIds.add(? parseHex32Node(inputsNode.get[i], path & ".inputs[" & $i & "]"))
    var notes: seq[Note] = @[]
    let outputsNode = yamlGetPathNode(payload, ["outputs"])
    if outputsNode.isNone or outputsNode.get.kind != ySequence:
      return err("deployment-settings: transfer outputs must be a sequence at " & path & ".outputs")
    for i in 0 ..< outputsNode.get.len:
      let outNode = outputsNode.get[i]
      if outNode.kind != yMapping:
        return err("deployment-settings: transfer output must be mapping at " & path & ".outputs[" & $i & "]")
      let valueNode = yamlGetPathNode(outNode, ["value"])
      let pkNode = yamlGetPathNode(outNode, ["pk"])
      if valueNode.isNone or pkNode.isNone:
        return err("deployment-settings: transfer output must contain value and pk at " & path & ".outputs[" & $i & "]")
      let value = ? parseUIntNode(valueNode.get, path & ".outputs[" & $i & "].value")
      notes.add(Note(
        value: Value(value),
        zkPublicKey: ? parseHex32Node(pkNode.get, path & ".outputs[" & $i & "].pk"),
      ))
    ok(createTransferOp(TransferPayload(
      inputs: Inputs(noteIds: noteIds),
      outputs: Outputs(notes: notes),
    )))
  of OpChannelInscribe:
    let channelIdNode = yamlGetPathNode(payload, ["channel_id"])
    let inscriptionNode = yamlGetPathNode(payload, ["inscription"])
    let parentNode = yamlGetPathNode(payload, ["parent"])
    let signerNode = yamlGetPathNode(payload, ["signer"])
    if channelIdNode.isNone or inscriptionNode.isNone or parentNode.isNone or signerNode.isNone:
      return err("deployment-settings: missing channel inscribe fields at " & path)
    ok(createChannelInscribeOp(ChannelInscribePayload(
      channelId: ? parseHex32Node(channelIdNode.get, path & ".channel_id"),
      inscription: ? parseByteSeqNode(inscriptionNode.get, path & ".inscription"),
      parent: ? parseHex32Node(parentNode.get, path & ".parent"),
      signer: ? parseEd25519PublicKeyNode(signerNode.get, path & ".signer"),
    )))
  of OpSdpDeclare:
    let serviceTypeNode = yamlGetPathNode(payload, ["service_type"])
    let locatorsNode = yamlGetPathNode(payload, ["locators"])
    let providerIdNode = yamlGetPathNode(payload, ["provider_id"])
    let zkIdNode = yamlGetPathNode(payload, ["zk_id"])
    let lockedNode = yamlGetPathNode(payload, ["locked_note_id"])
    if serviceTypeNode.isNone or locatorsNode.isNone or providerIdNode.isNone or zkIdNode.isNone or lockedNode.isNone:
      return err("deployment-settings: missing SDP declare fields at " & path)
    if serviceTypeNode.get.kind != yScalar:
      return err("deployment-settings: service_type must be scalar at " & path & ".service_type")
    let serviceType =
      case toLowerAscii(serviceTypeNode.get.content)
      of "bn": bn
      of "da": da
      else:
        return err("deployment-settings: unsupported service_type at " & path & ".service_type")
    if locatorsNode.get.kind != ySequence:
      return err("deployment-settings: locators must be sequence at " & path & ".locators")
    var locators: seq[Locator] = @[]
    for i in 0 ..< locatorsNode.get.len:
      let n = locatorsNode.get[i]
      if n.kind != yScalar:
        return err("deployment-settings: locator must be scalar at " & path & ".locators[" & $i & "]")
      var locator = newSeq[byte](n.content.len)
      for j in 0 ..< n.content.len:
        locator[j] = byte(n.content[j].ord)
      locators.add(locator)
    ok(createSdpDeclareOp(SdpDeclarePayload(
      serviceType: serviceType,
      locators: locators,
      providerId: ? parseEd25519PublicKeyNode(providerIdNode.get, path & ".provider_id"),
      zkId: ? parseHex32Node(zkIdNode.get, path & ".zk_id"),
      lockedNoteId: ? parseHex32Node(lockedNode.get, path & ".locked_note_id"),
    )))
  else:
    ## For currently-unused opcodes in deployment YAML, keep structural parsing strict
    ## while preserving previous default construction behavior.
    ok(defaultOpForOpcode(opcode))

func parseGenesisOpProof(
  node: YamlNode, idx: int, forOp: Op
): Result[OpProof, string] =

  let path = "cryptarchia.genesis_state.ops_proofs[" & $idx & "]"
  let expectedDefaultProof = defaultOpProofForOpcode(forOp.opcode)
  let expectedKind = expectedOpProofKindForOpcode(forOp.opcode)
  if node.kind == yScalar:
    ## TODO(mantle): `NoProof` was removed in Mantle v1.4; drop this compatibility
    ## branch once we receive the updated deployment file format.
    if node.content == "NoProof":
      return ok(expectedDefaultProof)
    return err("deployment-settings: unsupported scalar proof at " & path)

  if node.kind != yMapping:
    return err("deployment-settings: expected scalar or mapping proof at " & path)

  case expectedKind
  of opfTransfer:
    ok(OpProof(kind: opfTransfer, transferProof: ? parseZkSigNode(node, path)))
  of opfChannelDeposit:
    ok(OpProof(kind: opfChannelDeposit, channelDepositProof: ? parseZkSigNode(node, path)))
  of opfSdpWithdraw:
    ok(OpProof(kind: opfSdpWithdraw, sdpWithdrawProof: ? parseZkSigNode(node, path)))
  of opfSdpActive:
    ok(OpProof(kind: opfSdpActive, sdpActiveProof: ? parseZkSigNode(node, path)))
  of opfLeaderClaim:
    ok(OpProof(kind: opfLeaderClaim, proofOfClaimProof: ? parseZkSigNode(node, path)))
  of opfChannelInscribe:
    let edNode =
      if yamlGetPathNode(node, ["ed25519_sig"]).isSome: yamlGetPathNode(node, ["ed25519_sig"]).get
      else: node
    ok(OpProof(kind: opfChannelInscribe, ed25519SigProof: ? parseEd25519SignatureNode(edNode, path)))
  of opfSdpDeclare:
    let zkNode = yamlGetPathNode(node, ["zk_sig"])
    let edNode = yamlGetPathNode(node, ["ed25519_sig"])
    if zkNode.isNone or edNode.isNone:
      return err("deployment-settings: expected zk_sig and ed25519_sig at " & path)
    ok(OpProof(
      kind: opfSdpDeclare,
      declarationProof: ZkAndEd25519SigsProof(
        zkSig: ? parseZkSigNode(zkNode.get, path & ".zk_sig"),
        ed25519Sig: ? parseEd25519SignatureNode(edNode.get, path & ".ed25519_sig"),
      ),
    ))
  of opfChannelWithdraw, opfChannelConfig:
    # Keep compatibility fallback for older deployment fixtures lacking signatures/indexes.
    ok(expectedDefaultProof)

func parseDeploymentGenesisState*(root: YamlNode): Result[SignedMantleTx, string] =
  let gsOpt = yamlGetPathNode(root, ["cryptarchia", "genesis_state"])
  if gsOpt.isNone:
    return err("deployment-settings: missing cryptarchia.genesis_state")
  let gs = gsOpt.get
  if gs.kind != yMapping:
    return err("deployment-settings: cryptarchia.genesis_state must be a mapping")

  let opsOpt = yamlGetPathNode(root, ["cryptarchia", "genesis_state", "mantle_tx", "ops"])
  if opsOpt.isNone:
    return err("deployment-settings: missing cryptarchia.genesis_state.mantle_tx.ops")
  let opsNode = opsOpt.get
  if opsNode.kind != ySequence:
    return err("deployment-settings: cryptarchia.genesis_state.mantle_tx.ops must be a sequence")

  let proofsOpt = yamlGetPathNode(root, ["cryptarchia", "genesis_state", "ops_proofs"])
  if proofsOpt.isNone:
    return err("deployment-settings: missing cryptarchia.genesis_state.ops_proofs")
  let proofsNode = proofsOpt.get
  if proofsNode.kind != ySequence:
    return err("deployment-settings: cryptarchia.genesis_state.ops_proofs must be a sequence")

  var ops: seq[Op] = @[]
  for i in 0 ..< opsNode.len:
    let opNode = opsNode[i]
    if opNode.kind != yMapping:
      return err("deployment-settings: expected mapping at cryptarchia.genesis_state.mantle_tx.ops[" & $i & "]")

    let opcodeNode = yamlGetPathNode(opNode, ["opcode"])
    if opcodeNode.isNone or opcodeNode.get.kind != yScalar:
      return err("deployment-settings: expected scalar opcode at cryptarchia.genesis_state.mantle_tx.ops[" & $i & "].opcode")
    let opcodeVal =
      try:
        parseInt(opcodeNode.get.content)
      except ValueError:
        return err("deployment-settings: expected integer opcode at cryptarchia.genesis_state.mantle_tx.ops[" & $i & "].opcode")
    if opcodeVal < 0 or opcodeVal > high(Opcode).int:
      return err("deployment-settings: opcode must be >= 0 at cryptarchia.genesis_state.mantle_tx.ops[" & $i & "].opcode")

    let opcodeU8 = Opcode(opcodeVal)
    if not isSupportedOpcode(opcodeU8):
      return err("deployment-settings: unsupported opcode at mantletx op[" & $i &
        "]: " & $opcodeVal)
    ops.add(? parseGenesisOpPayload(opNode, i, opcodeU8))

  if proofsNode.len > ops.len:
    return err("deployment-settings: len(ops_proofs) must be <= len(ops)")

  var opProofs: seq[OpProof] = newSeq[OpProof](ops.len)
  for i in 0 ..< ops.len:
    opProofs[i] = defaultOpProofForOpcode(ops[i].opcode)
  for i in 0 ..< proofsNode.len:
    opProofs[i] = ? parseGenesisOpProof(proofsNode[i], i, ops[i])

  let executionGasPrice = ? reqInt(root, ["cryptarchia", "genesis_state", "mantle_tx", "execution_gas_price"])
  if executionGasPrice < 0:
    return err("deployment-settings: cryptarchia.genesis_state.mantle_tx.execution_gas_price must be >= 0")
  let storageGasPrice = ? reqInt(root, ["cryptarchia", "genesis_state", "mantle_tx", "storage_gas_price"])
  if storageGasPrice < 0:
    return err("deployment-settings: cryptarchia.genesis_state.mantle_tx.storage_gas_price must be >= 0")

  doAssert ops.len <= MantleMaxOps, "Mantle: too many ops for OpCount byte"
  let mantleTx = MantleTx(
    ops: ops,
    permanentStorageGasPrice: TokenValue(uint64(storageGasPrice)),
    executionGasPrice: TokenValue(uint64(executionGasPrice))
  )
  doAssert opProofs.len == mantleTx.ops.len,
    "signed mantle tx: len(ops_proofs) must be <= len(ops) before fill"
  ok(SignedMantleTx(tx: mantleTx, opProofs: opProofs))

{.pop.}
