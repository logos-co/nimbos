# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://opensource.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## **Genesis state:** ``cryptarchia.genesis_state`` is parsed into typed
## ``SignedMantleTx`` data.
## TODO(genesis-from-deployment): replace placeholder byte payload/proof content
## with canonical typed payload/proof decoding and validation.
## A follow-up change should parse YAML into those typed fields without changing
## the public load path: ``loadDeploymentSettings`` → ``parseDeploymentSettings`` →
## ``deploymentSettingsFromYaml``.

{.push raises: [].}

import
  std/[options, strutils],
  confutils/defs,
  results,
  stew/io2,
  yaml/dom,
  "../core/block/genesis",
  ./deployment_settings_helpers

export
  dom,
  genesis,
  parseDeploymentSettingsYaml,
  yamlGetPathNode,
  yamlGetPathScalar

type
  BlendSchedulerCover* = object
    messageFrequencyPerRound*: float
    intervalsForSafetyBuffer*: int

  BlendSchedulerDelayer* = object
    maximumReleaseDelayInRounds*: int

  BlendScheduler* = object
    cover*: BlendSchedulerCover
    delayer*: BlendSchedulerDelayer

  BlendCore* = object
    scheduler*: BlendScheduler
    minimumMessagesCoefficient*: int
    normalizationConstant*: float
    activityThresholdSensitivity*: int

  BlendCommon* = object
    numBlendLayers*: int
    minimumNetworkSize*: int
    protocolName*: string
    dataReplicationFactor*: int

  BlendSettings* = object
    common*: BlendCommon
    core*: BlendCore

  NetworkDeploymentSettings* = object
    kademliaProtocolName*: string
    identifyProtocolName*: string
    chainSyncProtocolName*: string

  EpochConfig* = object
    epochStakeDistributionStabilization*: int
    epochPeriodNonceBuffer*: int
    epochPeriodNonceStabilization*: int

  SlotActivationCoeff* = object
    numerator*: int
    denominator*: int

  BnServiceParams* = object
    lockPeriod*: int
    inactivityPeriod*: int
    retentionPeriod*: int
    timestamp*: int

  MinStake* = object
    threshold*: int
    timestamp*: int

  SdpConfig* = object
    bn*: BnServiceParams
    minStake*: MinStake

  CryptarchiaDeploymentSettings* = object
    epochConfig*: EpochConfig
    securityParam*: int
    slotActivationCoeff*: SlotActivationCoeff
    learningRate*: float
    sdpConfig*: SdpConfig
    gossipsubProtocol*: string
    genesisState*: SignedMantleTx

  TimeDeploymentSettings* = object
    slotDuration*: string
    chainStartTime*: string

  MempoolDeploymentSettings* = object
    pubsubTopic*: string

  DeploymentSettings* = object
    blend*: BlendSettings
    network*: NetworkDeploymentSettings
    cryptarchia*: CryptarchiaDeploymentSettings
    time*: TimeDeploymentSettings
    mempool*: MempoolDeploymentSettings

func validateDeploymentSettingsStructure(root: YamlNode): Result[void, string] =
  template needPath(path: openArray[string]) =
    if yamlGetPathNode(root, path).isNone:
      return err("deployment-settings: missing or invalid path: " & path.join("."))
  ? requireTopLevelMapping(root, "blend")
  ? requireTopLevelMapping(root, "network")
  ? requireTopLevelMapping(root, "cryptarchia")
  ? requireTopLevelMapping(root, "time")
  ? requireTopLevelMapping(root, "mempool")
  needPath(["blend", "common", "num_blend_layers"])
  needPath(["blend", "common", "minimum_network_size"])
  needPath(["blend", "common", "protocol_name"])
  needPath(["blend", "common", "data_replication_factor"])
  needPath(["blend", "core", "scheduler"])
  needPath(["blend", "core", "minimum_messages_coefficient"])
  needPath(["blend", "core", "normalization_constant"])
  needPath(["blend", "core", "activity_threshold_sensitivity"])
  needPath(["blend", "core", "scheduler", "cover", "message_frequency_per_round"])
  needPath(["blend", "core", "scheduler", "cover", "intervals_for_safety_buffer"])
  needPath(["blend", "core", "scheduler", "delayer", "maximum_release_delay_in_rounds"])
  needPath(["network", "kademlia_protocol_name"])
  needPath(["network", "identify_protocol_name"])
  needPath(["network", "chain_sync_protocol_name"])
  needPath(["cryptarchia", "epoch_config", "epoch_stake_distribution_stabilization"])
  needPath(["cryptarchia", "epoch_config", "epoch_period_nonce_buffer"])
  needPath(["cryptarchia", "epoch_config", "epoch_period_nonce_stabilization"])
  needPath(["cryptarchia", "security_param"])
  needPath(["cryptarchia", "slot_activation_coeff", "numerator"])
  needPath(["cryptarchia", "slot_activation_coeff", "denominator"])
  needPath(["cryptarchia", "learning_rate"])
  needPath(["cryptarchia", "sdp_config", "service_params", "BN", "lock_period"])
  needPath(["cryptarchia", "sdp_config", "service_params", "BN", "inactivity_period"])
  needPath(["cryptarchia", "sdp_config", "service_params", "BN", "retention_period"])
  needPath(["cryptarchia", "sdp_config", "service_params", "BN", "timestamp"])
  needPath(["cryptarchia", "sdp_config", "min_stake", "threshold"])
  needPath(["cryptarchia", "sdp_config", "min_stake", "timestamp"])
  needPath(["cryptarchia", "gossipsub_protocol"])
  needPath(["cryptarchia", "genesis_state", "mantle_tx", "ops"])
  needPath(["cryptarchia", "genesis_state", "mantle_tx", "execution_gas_price"])
  needPath(["cryptarchia", "genesis_state", "mantle_tx", "storage_gas_price"])
  needPath(["cryptarchia", "genesis_state", "ops_proofs"])
  needPath(["time", "slot_duration"])
  needPath(["time", "chain_start_time"])
  needPath(["mempool", "pubsub_topic"])
  ok()

func deploymentSettingsFromYaml(root: YamlNode): Result[DeploymentSettings, string] =
  let parsedGenesis = ? parseDeploymentGenesisState(root)
  ok(DeploymentSettings(
    blend: BlendSettings(
      common: BlendCommon(
        numBlendLayers: ? reqInt(root, ["blend", "common", "num_blend_layers"]),
        minimumNetworkSize: ? reqInt(root, ["blend", "common", "minimum_network_size"]),
        protocolName: ? reqScalar(root, ["blend", "common", "protocol_name"]),
        dataReplicationFactor: ? reqInt(root, ["blend", "common", "data_replication_factor"])
      ),
      core: BlendCore(
        scheduler: BlendScheduler(
          cover: BlendSchedulerCover(
            messageFrequencyPerRound: ? reqFloat(
              root, ["blend", "core", "scheduler", "cover", "message_frequency_per_round"]),
            intervalsForSafetyBuffer: ? reqInt(
              root, ["blend", "core", "scheduler", "cover", "intervals_for_safety_buffer"])
          ),
          delayer: BlendSchedulerDelayer(
            maximumReleaseDelayInRounds: ? reqInt(
              root, ["blend", "core", "scheduler", "delayer", "maximum_release_delay_in_rounds"])
          )
        ),
        minimumMessagesCoefficient: ? reqInt(root, ["blend", "core", "minimum_messages_coefficient"]),
        normalizationConstant: ? reqFloat(root, ["blend", "core", "normalization_constant"]),
        activityThresholdSensitivity: ? reqInt(root, ["blend", "core", "activity_threshold_sensitivity"])
      )
    ),
    network: NetworkDeploymentSettings(
      kademliaProtocolName: ? reqScalar(root, ["network", "kademlia_protocol_name"]),
      identifyProtocolName: ? reqScalar(root, ["network", "identify_protocol_name"]),
      chainSyncProtocolName: ? reqScalar(root, ["network", "chain_sync_protocol_name"])
    ),
    cryptarchia: CryptarchiaDeploymentSettings(
      epochConfig: EpochConfig(
        epochStakeDistributionStabilization: ? reqInt(
          root, ["cryptarchia", "epoch_config", "epoch_stake_distribution_stabilization"]),
        epochPeriodNonceBuffer: ? reqInt(
          root, ["cryptarchia", "epoch_config", "epoch_period_nonce_buffer"]),
        epochPeriodNonceStabilization: ? reqInt(
          root, ["cryptarchia", "epoch_config", "epoch_period_nonce_stabilization"])
      ),
      securityParam: ? reqInt(root, ["cryptarchia", "security_param"]),
      slotActivationCoeff: SlotActivationCoeff(
        numerator: ? reqInt(root, ["cryptarchia", "slot_activation_coeff", "numerator"]),
        denominator: ? reqInt(root, ["cryptarchia", "slot_activation_coeff", "denominator"])
      ),
      learningRate: ? reqFloat(root, ["cryptarchia", "learning_rate"]),
      sdpConfig: SdpConfig(
        bn: BnServiceParams(
          lockPeriod: ? reqInt(root, ["cryptarchia", "sdp_config", "service_params", "BN", "lock_period"]),
          inactivityPeriod: ? reqInt(root, ["cryptarchia", "sdp_config", "service_params", "BN", "inactivity_period"]),
          retentionPeriod: ? reqInt(root, ["cryptarchia", "sdp_config", "service_params", "BN", "retention_period"]),
          timestamp: ? reqInt(root, ["cryptarchia", "sdp_config", "service_params", "BN", "timestamp"])
        ),
        minStake: MinStake(
          threshold: ? reqInt(root, ["cryptarchia", "sdp_config", "min_stake", "threshold"]),
          timestamp: ? reqInt(root, ["cryptarchia", "sdp_config", "min_stake", "timestamp"])
        )
      ),
      gossipsubProtocol: ? reqScalar(root, ["cryptarchia", "gossipsub_protocol"]),
      genesisState: parsedGenesis
    ),
    time: TimeDeploymentSettings(
      slotDuration: ? reqScalar(root, ["time", "slot_duration"]),
      chainStartTime: ? reqScalar(root, ["time", "chain_start_time"])
    ),
    mempool: MempoolDeploymentSettings(
      pubsubTopic: ? reqScalar(root, ["mempool", "pubsub_topic"])
    )
  ))

proc parseDeploymentSettings*(text: string): Result[DeploymentSettings, string] =
  let root = ? parseDeploymentSettingsYaml(text)
  if root.kind != yMapping:
    return err("deployment-settings: expected top-level mapping")
  ? validateDeploymentSettingsStructure(root)
  deploymentSettingsFromYaml(root)

func validateDeploymentSettings*(ds: DeploymentSettings): Result[void, string] =
  template need(cond: bool, msg: string) =
    if not cond:
      return err(msg)
  need(ds.blend.common.numBlendLayers > 0, "blend.common.num_blend_layers must be > 0")
  need(ds.blend.common.minimumNetworkSize > 0, "blend.common.minimum_network_size must be > 0")
  need(ds.blend.common.dataReplicationFactor >= 0, "blend.common.data_replication_factor must be >= 0")
  need(ds.blend.core.minimumMessagesCoefficient > 0, "blend.core.minimum_messages_coefficient must be > 0")
  need(ds.blend.core.normalizationConstant > 0.0, "blend.core.normalization_constant must be > 0")
  need(ds.blend.core.activityThresholdSensitivity > 0, "blend.core.activity_threshold_sensitivity must be > 0")
  need(ds.blend.core.scheduler.cover.messageFrequencyPerRound > 0.0,
    "blend.core.scheduler.cover.message_frequency_per_round must be > 0")
  need(ds.blend.core.scheduler.cover.intervalsForSafetyBuffer > 0,
    "blend.core.scheduler.cover.intervals_for_safety_buffer must be > 0")
  need(ds.blend.core.scheduler.delayer.maximumReleaseDelayInRounds > 0,
    "blend.core.scheduler.delayer.maximum_release_delay_in_rounds must be > 0")

  need(ds.cryptarchia.epochConfig.epochStakeDistributionStabilization > 0,
    "cryptarchia.epoch_config.epoch_stake_distribution_stabilization must be > 0")
  need(ds.cryptarchia.epochConfig.epochPeriodNonceBuffer > 0,
    "cryptarchia.epoch_config.epoch_period_nonce_buffer must be > 0")
  need(ds.cryptarchia.epochConfig.epochPeriodNonceStabilization > 0,
    "cryptarchia.epoch_config.epoch_period_nonce_stabilization must be > 0")
  need(ds.cryptarchia.securityParam > 0, "cryptarchia.security_param must be > 0")
  need(ds.cryptarchia.slotActivationCoeff.numerator > 0,
    "cryptarchia.slot_activation_coeff.numerator must be > 0")
  need(ds.cryptarchia.slotActivationCoeff.denominator > 0,
    "cryptarchia.slot_activation_coeff.denominator must be > 0")
  need(ds.cryptarchia.learningRate > 0.0, "cryptarchia.learning_rate must be > 0")
  need(ds.cryptarchia.sdpConfig.bn.lockPeriod > 0,
    "cryptarchia.sdp_config.service_params.BN.lock_period must be > 0")
  need(ds.cryptarchia.sdpConfig.bn.inactivityPeriod > 0,
    "cryptarchia.sdp_config.service_params.BN.inactivity_period must be > 0")
  need(ds.cryptarchia.sdpConfig.bn.retentionPeriod > 0,
    "cryptarchia.sdp_config.service_params.BN.retention_period must be > 0")
  need(ds.cryptarchia.sdpConfig.bn.timestamp >= 0,
    "cryptarchia.sdp_config.service_params.BN.timestamp must be >= 0")
  need(ds.cryptarchia.sdpConfig.minStake.threshold > 0,
    "cryptarchia.sdp_config.min_stake.threshold must be > 0")
  need(ds.cryptarchia.sdpConfig.minStake.timestamp >= 0,
    "cryptarchia.sdp_config.min_stake.timestamp must be >= 0")
  need(ds.network.kademliaProtocolName.len > 0, "empty network.kademlia_protocol_name")
  need(ds.network.identifyProtocolName.len > 0, "empty network.identify_protocol_name")
  need(ds.network.chainSyncProtocolName.len > 0, "empty network.chain_sync_protocol_name")
  need(ds.time.slotDuration.len > 0, "empty time.slot_duration")
  need(ds.time.chainStartTime.len > 0, "empty time.chain_start_time")
  need(ds.mempool.pubsubTopic.len > 0, "empty mempool.pubsub_topic")
  need(ds.cryptarchia.gossipsubProtocol.len > 0, "empty cryptarchia.gossipsub_protocol")
  need(ds.blend.common.protocolName.len > 0, "empty blend.common.protocol_name")
  need(ds.blend.common.protocolName.startsWith("/"), "blend.common.protocol_name must start with '/'")
  need(ds.network.kademliaProtocolName.startsWith("/"), "network.kademlia_protocol_name must start with '/'")
  need(ds.network.identifyProtocolName.startsWith("/"), "network.identify_protocol_name must start with '/'")
  need(
    ds.network.chainSyncProtocolName.startsWith("/"),
    "network.chain_sync_protocol_name must start with '/'"
  )
  need(ds.mempool.pubsubTopic.startsWith("/"), "mempool.pubsub_topic must start with '/'")
  need(ds.cryptarchia.gossipsubProtocol.startsWith("/"), "cryptarchia.gossipsub_protocol must start with '/'")

  let smt = ds.cryptarchia.genesisState
  need(smt.tx.ops.len > 0,
    "cryptarchia.genesis_state.mantle_tx.ops must be non-empty")
  let genesisProofCount = smt.opProofs.len
  let genesisOpCount = smt.tx.ops.len
  need(
    genesisProofCount <= genesisOpCount,
    "cryptarchia.genesis_state: len(ops_proofs) must be <= len(ops)"
  )
  for i in 0 ..< smt.opProofs.len:
    let expectedKind = expectedOpProofKindForOpcode(smt.tx.ops[i].opcode)
    let proofOk = smt.opProofs[i].kind == expectedKind
    need(
      proofOk,
      "cryptarchia.genesis_state: ops_proofs[" & $i & "] does not match ProofFor(mantle_tx.ops[" & $i & "])"
    )
  need(smt.tx.executionGasPrice == TokenValue(0'u64),
    "cryptarchia.genesis_state.mantle_tx.execution_gas_price must be 0 for genesis")
  need(smt.tx.permanentStorageGasPrice == TokenValue(0'u64),
    "cryptarchia.genesis_state.mantle_tx.storage_gas_price must be 0 for genesis")
  need(smt.tx.ops.len >= 2,
    "cryptarchia.genesis_state.mantle_tx.ops must contain at least transfer and inscription")
  need(
    smt.tx.ops[0].opcode == OpTransfer,
    "cryptarchia.genesis_state.mantle_tx.ops[0] must be transfer")
  need(
    smt.tx.ops[1].opcode == OpChannelInscribe,
    "cryptarchia.genesis_state.mantle_tx.ops[1] must be channel_inscribe")
  if smt.tx.ops.len > 2:
    for i in 2 ..< smt.tx.ops.len:
      need(
        smt.tx.ops[i].opcode == OpSdpDeclare,
        "cryptarchia.genesis_state.mantle_tx.ops[" & $i & "] must be sdp_declare")

  ok()

proc loadDeploymentSettings*(deploymentSettingsFile: InputFile): Result[DeploymentSettings, string] =
  let path = string(deploymentSettingsFile)
  let textRes = readAllChars(path)
  if textRes.isErr():
    return err("deployment-settings: cannot read " & path & ": " & ioErrorMsg(textRes.error))
  let text = textRes.get()
  let ds = ? parseDeploymentSettings(text)
  ? validateDeploymentSettings(ds)
  ok(ds)

{.pop.}
