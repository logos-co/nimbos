# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[options, strutils],
  chronos,
  results,
  stew/byteutils,
  yaml/[dom, loading],
  libp2p/multiaddress,
  libp2p/crypto/ed25519/ed25519,
  ../chain/genesis

export genesis, chronos

func yamlGetPathNode*(root: YamlNode, keys: openArray[string]): Option[YamlNode] =
  var cur = root
  for k in keys:
    if cur.isNil or cur.kind != yMapping:
      return none(YamlNode)
    try:
      cur = cur[k]
    except KeyError:
      return none(YamlNode)
  some(cur)

func yamlGetPathScalar*(root: YamlNode, keys: openArray[string]): Option[string] =
  if keys.len == 0:
    return none(string)
  let node = yamlGetPathNode(root, keys)
  if node.isNone or node.get.kind != yScalar:
    return none(string)
  some(node.get.content)


proc parseDeploymentSettingsYaml*(text: string): Result[YamlNode, string] =
  try:
    var root: YamlNode
    load(text, root)
    ok(root)
  except YamlConstructionError, YamlParserError, IOError, OSError:
    err("deployment-settings: " & getCurrentExceptionMsg())


func requireTopLevelMapping*(root: YamlNode, name: string): Result[void, string] =
  if root.kind != yMapping:
    return err("deployment-settings: expected top-level mapping")
  try:
    let n = root[name]
    if n.kind != yMapping:
      return err("deployment-settings: expected top-level section '" & name & "' to be a mapping")
  except KeyError:
    return err("deployment-settings: missing top-level section: " & name)
  ok()


func reqScalar*(root: YamlNode, path: openArray[string]): Result[string, string] =
  let s = yamlGetPathScalar(root, path)
  if s.isNone:
    return err("deployment-settings: missing or non-scalar " & path.join("."))
  ok(s.get)

template reqParsed(
    root: YamlNode,
    path: openArray[string],
    parse: untyped,
    expectedType: string
): untyped =
  let s = ? reqScalar(root, path)
  try:
    ok(parse(s))
  except ValueError:
    err("deployment-settings: expected " & expectedType & " at " & path.join("."))

func reqInt*(root: YamlNode, path: openArray[string]): Result[int, string] =
  reqParsed(root, path, parseInt, "integer")

func reqFloat*(root: YamlNode, path: openArray[string]): Result[float, string] =
  reqParsed(root, path, parseFloat, "float")

proc parseSlotDurationSeconds*(s: string): Duration {.raises: [ValueError].} =
  ## ``time.slot_duration`` YAML scalar: seconds as a float (e.g. ``'1.0'``).
  let secs = parseFloat(s)
  nanoseconds(int64(secs * float(nanoseconds(seconds(1)))))

func reqSlotDuration*(root: YamlNode, path: openArray[string]): Result[Duration, string] =
  reqParsed(root, path, parseSlotDurationSeconds, "slot duration in seconds")


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

func parseFieldElementNode(node: YamlNode, path: string): Result[FieldElement, string] =
  let bytes = ? parseHex32Node(node, path)
  let parsed = FieldElement.fromBytes(bytes)
  if parsed.isNone:
    return err("deployment-settings: field element exceeds BN254 scalar modulus at " & path)
  ok(parsed.get())

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

func parseBedrockVersionScalar(node: YamlNode, path: string): Result[uint8, string] =
  if node.kind != yScalar:
    return err("deployment-settings: expected scalar at " & path)
  case toLowerAscii(strip(node.content))
  of "bedrock":
    ok(GenesisBedrockVersion)
  else:
    err("deployment-settings: unknown bedrock header.version at " & path & ": " & node.content)

func parseHex128ProofNode(node: YamlNode, path: string): Result[CompressedGroth16Proof, string] =
  if node.kind != yScalar:
    return err("deployment-settings: expected hex scalar at " & path)
  var proof: CompressedGroth16Proof
  let s = node.content
  if s.len != CompressedGroth16ProofBytes * 2:
    return err(
      "deployment-settings: expected " & $(CompressedGroth16ProofBytes * 2) & " hex chars at " & path)
  try:
    hexToByteArrayStrict(s, proof)
  except ValueError:
    return err("deployment-settings: invalid Groth16 proof hex at " & path)
  ok(proof)

func parseGenesisBlockHeaderFromYaml(hdr: YamlNode, pathPrefix: string): Result[Header, string] =
  if hdr.kind != yMapping:
    return err("deployment-settings: expected mapping at " & pathPrefix)
  let verNode = yamlGetPathNode(hdr, ["version"])
  if verNode.isNone:
    return err("deployment-settings: missing " & pathPrefix & ".version")
  let bedrockVer = ? parseBedrockVersionScalar(verNode.get, pathPrefix & ".version")
  let parentNode = yamlGetPathNode(hdr, ["parent_block"])
  if parentNode.isNone:
    return err("deployment-settings: missing " & pathPrefix & ".parent_block")
  let parentBlock = BlockId(? parseHex32Node(parentNode.get, pathPrefix & ".parent_block"))
  let slotNode = yamlGetPathNode(hdr, ["slot"])
  if slotNode.isNone:
    return err("deployment-settings: missing " & pathPrefix & ".slot")
  let slot = SlotNumber(? parseUIntNode(slotNode.get, pathPrefix & ".slot"))
  let rootNode = yamlGetPathNode(hdr, ["block_root"])
  if rootNode.isNone:
    return err("deployment-settings: missing " & pathPrefix & ".block_root")
  let blockRoot = ? parseHex32Node(rootNode.get, pathPrefix & ".block_root")
  let polOpt = yamlGetPathNode(hdr, ["proof_of_leadership"])
  if polOpt.isNone:
    return err("deployment-settings: missing " & pathPrefix & ".proof_of_leadership")
  let pol = polOpt.get
  if pol.kind != yMapping:
    return err("deployment-settings: expected mapping at " & pathPrefix & ".proof_of_leadership")
  let polPath = pathPrefix & ".proof_of_leadership"
  let proofNode = yamlGetPathNode(pol, ["proof"])
  if proofNode.isNone:
    return err("deployment-settings: missing " & polPath & ".proof")
  let polProof = ? parseHex128ProofNode(proofNode.get, polPath & ".proof")
  let entNode = yamlGetPathNode(pol, ["entropy_contribution"])
  if entNode.isNone:
    return err("deployment-settings: missing " & polPath & ".entropy_contribution")
  let entropy = (? parseHex32Node(entNode.get, polPath & ".entropy_contribution"))
  let lkNode = yamlGetPathNode(pol, ["leader_key"])
  if lkNode.isNone:
    return err("deployment-settings: missing " & polPath & ".leader_key")
  let leaderKey = ? parseEd25519PublicKeyNode(lkNode.get, polPath & ".leader_key")
  let vNode = yamlGetPathNode(pol, ["voucher_cm"])
  if vNode.isNone:
    return err("deployment-settings: missing " & polPath & ".voucher_cm")
  let voucher: RewardVoucher = ? parseHex32Node(vNode.get, polPath & ".voucher_cm")
  ok(Header(
    bedrockVersion: bedrockVer,
    parentBlock: parentBlock,
    slot: slot,
    blockRoot: blockRoot,
    proofOfLeadership: ProofOfLeadership(
      leaderVoucher: voucher,
      entropyContribution: entropy,
      proof: polProof,
      leaderKey: leaderKey,
    ),
  ))

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

func parseGenesisOpPayload(
    opNode: YamlNode, idx: int, opcode: Opcode, opsPathPrefix: string
): Result[Op, string] =
  let path = opsPathPrefix & "[" & $idx & "].payload"
  let payloadNode = yamlGetPathNode(opNode, ["payload"])
  if payloadNode.isNone:
    return err("deployment-settings: missing payload at " & path)
  let payload = payloadNode.get
  if payload.kind != yMapping:
    return err("deployment-settings: payload must be a mapping at " & path)
  if payload.len == 0:
    return ok(defaultOpForOpcode(opcode))
  case opcode
  of OpTransfer:
    var noteIds: seq[NoteId] = @[]
    let inputsNode = yamlGetPathNode(payload, ["inputs"])
    if inputsNode.isSome:
      if inputsNode.get.kind != ySequence:
        return err("deployment-settings: transfer inputs must be a sequence at " & path & ".inputs")
      for i in 0 ..< inputsNode.get.len:
        noteIds.add(? parseFieldElementNode(inputsNode.get[i], path & ".inputs[" & $i & "]"))
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
        zkPublicKey: ? parseFieldElementNode(pkNode.get, path & ".outputs[" & $i & "].pk"),
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
    let inscriptionBytes =
      if inscriptionNode.get.kind == yScalar:
        try:
          Result[seq[byte], string].ok(hexToSeqByte(inscriptionNode.get.content))
        except ValueError:
          Result[seq[byte], string].err(
            "deployment-settings: invalid inscription hex at " & path & ".inscription")
      else:
        parseByteSeqNode(inscriptionNode.get, path & ".inscription")
    ok(createChannelInscribeOp(ChannelInscribePayload(
      channelId: ? parseHex32Node(channelIdNode.get, path & ".channel_id"),
      inscription: ? inscriptionBytes,
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
      else:
        return err("deployment-settings: unsupported service_type at " & path & ".service_type")
    if locatorsNode.get.kind != ySequence:
      return err("deployment-settings: locators must be sequence at " & path & ".locators")
    var locators: seq[Locator] = @[]
    for i in 0 ..< locatorsNode.get.len:
      let n = locatorsNode.get[i]
      if n.kind != yScalar:
        return err("deployment-settings: locator must be scalar at " & path & ".locators[" & $i & "]")
      let locator = MultiAddress.init(n.content).valueOr:
        return err("deployment-settings: invalid multiaddr at " &
          path & ".locators[" & $i & "]: " & error)
      locators.add(locator)
    ok(createSdpDeclareOp(SdpDeclarePayload(
      serviceType: serviceType,
      locators: locators,
      providerId: ? parseEd25519PublicKeyNode(providerIdNode.get, path & ".provider_id"),
      zkId: ? parseFieldElementNode(zkIdNode.get, path & ".zk_id"),
      lockedNoteId: ? parseFieldElementNode(lockedNode.get, path & ".locked_note_id"),
    )))
  else:
    ok(defaultOpForOpcode(opcode))

func parseGenesisOpProof(
    node: YamlNode, idx: int, forOp: Op, proofsPathPrefix: string
): Result[OpProof, string] =
  let path = proofsPathPrefix & "[" & $idx & "]"
  let expectedDefaultProof = defaultOpProofForOpcode(forOp.opcode)
  let expectedKind = expectedOpProofKindForOpcode(forOp.opcode)
  if node.kind == yScalar:
    ## TODO(mantle): `NoProof` was removed in Mantle v1.4; drop this compatibility
    ## branch once we receive the updated deployment file format.
    if node.content == "NoProof":
      return ok(expectedDefaultProof)
    if expectedKind == opfChannelInscribe:
      return ok(OpProof(
        kind: opfChannelInscribe,
        ed25519SigProof: ? parseEd25519SignatureNode(node, path),
      ))
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
    ok(expectedDefaultProof)

func validateCryptarchiaGenesisYaml*(root: YamlNode): Result[void, string] =
  let gbOpt = yamlGetPathNode(root, ["cryptarchia", "genesis_block"])
  if gbOpt.isNone:
    return err("deployment-settings: missing cryptarchia.genesis_block")
  let blockNode = gbOpt.get
  if blockNode.kind != yMapping:
    return err("deployment-settings: cryptarchia.genesis_block must be a mapping")
  template needUnder(node: YamlNode, keys: openArray[string], ctx: string) =
    if yamlGetPathNode(node, keys).isNone:
      return err("deployment-settings: missing " & ctx)
  needUnder(blockNode, ["header"], "cryptarchia.genesis_block.header")
  needUnder(blockNode, ["signature"], "cryptarchia.genesis_block.signature")
  let hdr = yamlGetPathNode(blockNode, ["header"]).get
  if hdr.kind != yMapping:
    return err("deployment-settings: cryptarchia.genesis_block.header must be a mapping")
  needUnder(hdr, ["version"], "cryptarchia.genesis_block.header.version")
  needUnder(hdr, ["parent_block"], "cryptarchia.genesis_block.header.parent_block")
  needUnder(hdr, ["slot"], "cryptarchia.genesis_block.header.slot")
  needUnder(hdr, ["block_root"], "cryptarchia.genesis_block.header.block_root")
  needUnder(hdr, ["proof_of_leadership"], "cryptarchia.genesis_block.header.proof_of_leadership")
  let pol = yamlGetPathNode(hdr, ["proof_of_leadership"]).get
  if pol.kind != yMapping:
    return err("deployment-settings: cryptarchia.genesis_block.header.proof_of_leadership must be a mapping")
  needUnder(pol, ["proof"], "cryptarchia.genesis_block.header.proof_of_leadership.proof")
  needUnder(
    pol, ["entropy_contribution"],
    "cryptarchia.genesis_block.header.proof_of_leadership.entropy_contribution")
  needUnder(pol, ["leader_key"], "cryptarchia.genesis_block.header.proof_of_leadership.leader_key")
  needUnder(pol, ["voucher_cm"], "cryptarchia.genesis_block.header.proof_of_leadership.voucher_cm")
  let txSeqOpt = yamlGetPathNode(blockNode, ["transactions"])
  if txSeqOpt.isNone:
    return err("deployment-settings: missing cryptarchia.genesis_block.transactions")
  let txSeq = txSeqOpt.get
  if txSeq.kind != ySequence or txSeq.len == 0:
    return err(
      "deployment-settings: cryptarchia.genesis_block.transactions must be a non-empty sequence")
  let tx0 = txSeq[0]
  if tx0.kind != yMapping:
    return err(
      "deployment-settings: cryptarchia.genesis_block.transactions[0] must be a mapping")
  needUnder(tx0, ["mantle_tx"], "cryptarchia.genesis_block.transactions[0].mantle_tx")
  needUnder(tx0, ["ops_proofs"], "cryptarchia.genesis_block.transactions[0].ops_proofs")
  let mantle = yamlGetPathNode(tx0, ["mantle_tx"]).get
  if mantle.kind != yMapping:
    return err("deployment-settings: cryptarchia.genesis_block.transactions[0].mantle_tx must be a mapping")
  needUnder(mantle, ["ops"], "cryptarchia.genesis_block.transactions[0].mantle_tx.ops")
  needUnder(
    mantle, ["execution_gas_price"],
    "cryptarchia.genesis_block.transactions[0].mantle_tx.execution_gas_price")
  needUnder(
    mantle, ["storage_gas_price"],
    "cryptarchia.genesis_block.transactions[0].mantle_tx.storage_gas_price")
  ok()

func parseSignedMantleTxFromOpsYaml*(
    opsNode: YamlNode,
    proofsNode: YamlNode,
    mantleGasNode: YamlNode,
    opsPathPrefix: string,
    proofsPathPrefix: string,
): Result[SignedMantleTx, string] =
  if opsNode.kind != ySequence:
    return err("deployment-settings: " & opsPathPrefix & " must be a sequence")
  if proofsNode.kind != ySequence:
    return err("deployment-settings: " & proofsPathPrefix & " must be a sequence")

  var ops: seq[Op] = @[]
  for i in 0 ..< opsNode.len:
    let opNode = opsNode[i]
    if opNode.kind != yMapping:
      return err("deployment-settings: expected mapping at " & opsPathPrefix & "[" & $i & "]")

    let opcodeNode = yamlGetPathNode(opNode, ["opcode"])
    if opcodeNode.isNone or opcodeNode.get.kind != yScalar:
      return err("deployment-settings: expected scalar opcode at " & opsPathPrefix & "[" & $i & "].opcode")
    let opcodeVal =
      try:
        parseInt(opcodeNode.get.content)
      except ValueError:
        return err("deployment-settings: expected integer opcode at " & opsPathPrefix & "[" & $i & "].opcode")
    if opcodeVal < 0 or opcodeVal > high(Opcode).int:
      return err("deployment-settings: opcode must be >= 0 at " & opsPathPrefix & "[" & $i & "].opcode")

    let opcodeU8 = Opcode(opcodeVal)
    if not isSupportedOpcode(opcodeU8):
      return err("deployment-settings: unsupported opcode at mantletx op[" & $i &
        "]: " & $opcodeVal)
    ops.add(? parseGenesisOpPayload(opNode, i, opcodeU8, opsPathPrefix))

  if proofsNode.len > ops.len:
    return err("deployment-settings: len(" & proofsPathPrefix & ") must be <= len(" & opsPathPrefix & ")")

  var opProofs: seq[OpProof] = newSeq[OpProof](ops.len)
  for i in 0 ..< ops.len:
    opProofs[i] = defaultOpProofForOpcode(ops[i].opcode)
  for i in 0 ..< proofsNode.len:
    opProofs[i] = ? parseGenesisOpProof(proofsNode[i], i, ops[i], proofsPathPrefix)

  let executionGasPrice = ? reqInt(mantleGasNode, ["execution_gas_price"])
  if executionGasPrice < 0:
    return err("deployment-settings: mantle_tx.execution_gas_price must be >= 0")
  let storageGasPrice = ? reqInt(mantleGasNode, ["storage_gas_price"])
  if storageGasPrice < 0:
    return err("deployment-settings: mantle_tx.storage_gas_price must be >= 0")

  doAssert ops.len <= MantleMaxOps, "Mantle: too many ops for OpCount byte"
  let mantleTx = MantleTx(
    ops: ops,
    permanentStorageGasPrice: TokenValue(uint64(storageGasPrice)),
    executionGasPrice: TokenValue(uint64(executionGasPrice)),
  )
  doAssert opProofs.len == mantleTx.ops.len,
    "signed mantle tx: len(ops_proofs) must be <= len(ops) before fill"
  ok(SignedMantleTx(tx: mantleTx, opProofs: opProofs))

func parseDeploymentGenesisState*(root: YamlNode): Result[GenesisState, string] =
  let gbOpt = yamlGetPathNode(root, ["cryptarchia", "genesis_block"])
  if gbOpt.isNone:
    return err("deployment-settings: missing cryptarchia.genesis_block")
  let gb = gbOpt.get
  if gb.kind != yMapping:
    return err("deployment-settings: cryptarchia.genesis_block must be a mapping")
  let hdrNode = yamlGetPathNode(gb, ["header"])
  if hdrNode.isNone:
    return err("deployment-settings: missing cryptarchia.genesis_block.header")
  let signedHeader = ? parseGenesisBlockHeaderFromYaml(
    hdrNode.get, "cryptarchia.genesis_block.header")
  let sigNode = yamlGetPathNode(gb, ["signature"])
  if sigNode.isNone:
    return err("deployment-settings: missing cryptarchia.genesis_block.signature")
  let blockSig = ? parseEd25519SignatureNode(sigNode.get, "cryptarchia.genesis_block.signature")
  let txSeqOpt = yamlGetPathNode(gb, ["transactions"])
  if txSeqOpt.isNone or txSeqOpt.get.kind != ySequence or txSeqOpt.get.len == 0:
    return err(
      "deployment-settings: cryptarchia.genesis_block.transactions must be a non-empty sequence")
  let tx0 = txSeqOpt.get[0]
  if tx0.kind != yMapping:
    return err(
      "deployment-settings: cryptarchia.genesis_block.transactions[0] must be a mapping")
  let mantleOpt = yamlGetPathNode(tx0, ["mantle_tx"])
  let proofsOpt = yamlGetPathNode(tx0, ["ops_proofs"])
  if mantleOpt.isNone or proofsOpt.isNone:
    return err(
      "deployment-settings: cryptarchia.genesis_block.transactions[0] needs mantle_tx and ops_proofs")
  let mantle = mantleOpt.get
  if mantle.kind != yMapping:
    return err(
      "deployment-settings: cryptarchia.genesis_block.transactions[0].mantle_tx must be a mapping")
  let opsOpt = yamlGetPathNode(mantle, ["ops"])
  if opsOpt.isNone:
    return err(
      "deployment-settings: missing cryptarchia.genesis_block.transactions[0].mantle_tx.ops")
  let smt = ? parseSignedMantleTxFromOpsYaml(
    opsOpt.get,
    proofsOpt.get,
    mantle,
    "cryptarchia.genesis_block.transactions[0].mantle_tx.ops",
    "cryptarchia.genesis_block.transactions[0].ops_proofs",
  )
  let fpOpt = yamlGetPathNode(root, ["cryptarchia", "faucet_pk"])
  if fpOpt.isNone:
    return err("deployment-settings: missing cryptarchia.faucet_pk")
  let faucetPk = ? parseFieldElementNode(fpOpt.get, "cryptarchia.faucet_pk")
  ok(GenesisState(
    signedMantleTx: smt,
    faucetZkPublicKey: faucetPk,
    header: signedHeader,
    blockSignature: blockSig,
  ))

{.pop.}
