# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[options, unicode, uri],
  metrics,
  results,
  chronicles, chronicles/options as chroniclesOptions,
  confutils, confutils/defs, confutils/std/net,
  confutils/toml/defs as confTomlDefs,
  toml_serialization/std/net as confTomlNet,
  toml_serialization/std/uri as confTomlUri,
  serialization/errors,
  stew/[io2, byteutils],
  eth/net/nat, # TODO(logos-chain-networking): replace NatConfig/eth-net-nat with Logos-native reachability config
  eth/enr/enr,
  json_serialization, json_serialization/std/net as jsnet,
  chronos/transports/common,
  ./deployment/deployment_settings,
  ./binary_common,
  ./zk/circuits

from std/os import dirExists, getDataDir, `/`
from std/strutils import parseBiggestUInt, replace

export
  uri, nat, enr,
  enabledLogLevel,
  defs, parseCmdArg, completeCmdArg,
  confTomlDefs, confTomlNet, confTomlUri, jsnet,
  deployment_settings,
  binary_common

const
  # TODO: How should we select between IPv4 and IPv6
  # Maybe there should be a config option for this.
  defaultAdminListenAddress* = (static parseIpAddress("127.0.0.1"))
  defaultSigningNodeRequestTimeout* = 60
  defaultGasLimit* = 60_000_000
  defaultAdminListenAddressDesc* = $defaultAdminListenAddress
  ## Default ``--deployment-settings`` path (canonical cfgsync layout; run from repo root or override).
  defaultDeploymentSettingsPath* = "config/deployment-settings.yaml"

when defined(windows):
  {.pragma: windowsOnly.}
  {.pragma: posixOnly, hidden.}
else:
  {.pragma: windowsOnly, hidden.}
  {.pragma: posixOnly.}

proc defaultCircuitsDir*(): InputDir =
  ## Platform-aware data location (`$XDG_DATA_HOME` or `~/.local/share` on
  ## Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on Windows),
  ## suffixed with the pinned bundle version. XDG `data` (not `cache`) because
  ## the bundle is essential for the prover; losing it breaks the node.
  InputDir(getDataDir() / "logos-blockchain-circuits" / ExpectedCircuitsVersion)

type
  BNStartUpCmd* {.pure.} = enum
    lbNode ## default startup command (CLI name derived by confutils, e.g. `lb-node`)

  LBNodeConf* = object
    # When updating, coordinate option names with EL and other binaries
    configFile* {.
      desc: "Loads the configuration from a TOML file"
      name: "config-file" .}: Option[InputFile]

    logLevel* {.
      desc: "Sets the log level for process and topics (e.g. \"DEBUG; TRACE:discv5,libp2p; REQUIRED:none; DISABLED:none\")"
      defaultValue: "INFO"
      name: "log-level" .}: string

    logStdout* {.
      hidden
      desc: "Specifies what kind of logs should be written to stdout (auto, colors, nocolors, json)"
      defaultValueDesc: "auto"
      defaultValue: StdoutLogKind.Auto
      name: "log-format" .}: StdoutLogKind

    logFile* {.
      desc: "Specifies a path for the written JSON log file (deprecated)"
      name: "log-file" .}: Option[OutFile]

    eth2Network* {.
      desc: "The Eth2 network to join"
      defaultValueDesc: "mainnet"
      name: "network" .}: Option[string]

    dataDirFlag* {.
      desc: "The directory where nimbus will store all blockchain data"
      abbr: "d"
      name: "data-dir" .}: Option[OutDir]

    validatorsDirFlag* {.
      desc: "A directory containing validator keystores"
      name: "validators-dir" .}: Option[InputDir]

    verifyingWeb3Signers* {.
      desc: "Remote Web3Signer URL that will be used as a source of validators"
      name: "verifying-web3-signer-url" .}: seq[Uri]

    provenBlockProperties* {.
      desc: "The field path of a block property that will be sent for verification to the verifying Web3Signer (for example \".execution_payload.fee_recipient\")"
      name: "proven-block-property" .}: seq[string]

    web3Signers* {.
      desc: "Remote Web3Signer URL that will be used as a source of validators"
      name: "web3-signer-url" .}: seq[Uri]

    web3signerUpdateInterval* {.
      desc: "Number of seconds between validator list updates"
      name: "web3-signer-update-interval"
      defaultValue: 3600 .}: Natural

    secretsDirFlag* {.
      desc: "A directory containing validator keystore passwords"
      name: "secrets-dir" .}: Option[InputDir]

    eraDirFlag* {.
      hidden
      desc: "A directory containing era files"
      name: "era-dir" .}: Option[InputDir]

    web3ForcePolling* {.
      hidden
      name: "web3-force-polling" .}: Option[bool]

    noEl* {.
      defaultValue: false
      desc: "Don't use an EL. The node will remain optimistically synced and won't be able to perform validator duties"
      name: "no-el" .}: bool

    optimistic* {.
      hidden # deprecated > 22.12
      desc: "Run the node in optimistic mode, allowing it to optimistically sync without an execution client (flag deprecated, always on)"
      name: "optimistic".}: Option[bool]

    requireEngineAPI* {.
      hidden  # Deprecated > 22.9
      desc: "Require Nimbus to be configured with an Engine API end-point after the Bellatrix fork epoch"
      name: "require-engine-api-in-bellatrix" .}: Option[bool]

    nonInteractive* {.
      desc: "Do not display interactive prompts. Quit on missing configuration"
      name: "non-interactive" .}: bool

    netKeyFile* {.
      desc: "Source of network (secp256k1) private key file " &
            "(random|<path>)"
      defaultValue: "random",
      name: "netkey-file" .}: string

    netKeyInsecurePassword* {.
      desc: "Use pre-generated INSECURE password for network private key file"
      defaultValue: false,
      name: "insecure-netkey-password" .}: bool

    agentString* {.
      defaultValue: "nimbus",
      desc: "Node agent string which is used as identifier in network"
      name: "agent-string" .}: string

    subscribeAllSubnets* {.
      defaultValue: false,
      desc: "Subscribe to all subnet topics when gossiping"
      name: "subscribe-all-subnets" .}: bool

    peerdasSupernode* {.
      defaultValue: false,
      desc: "Subscribe to all column subnets, thereby becoming a PeerDAS supernode"
      name: "peerdas-supernode" .}: bool

    lightSupernode* {.
      defaultValue: false,
      desc: "Subscribe to the first half of column subnets"
      name: "light-supernode" .}: bool

    numThreads* {.
      defaultValue: 0,
      desc: "Number of worker threads (\"0\" = use as many threads as there are CPU cores available)"
      name: "num-threads" .}: int

    # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.3/src/engine/authentication.md#key-distribution
    jwtSecret* {.
      desc: "A file containing the hex-encoded 256 bit secret key to be used for verifying/generating JWT tokens"
      name: "jwt-secret" .}: Option[InputFile]

    case cmd* {.
      command
      defaultValue: BNStartUpCmd.lbNode .}: BNStartUpCmd

    of BNStartUpCmd.lbNode:
      runAsServiceFlag* {.
        windowsOnly
        defaultValue: false,
        desc: "Run as a Windows service"
        name: "run-as-service" .}: bool

      bootstrapNodes* {.
        desc: "Specifies one or more bootstrap nodes to use when connecting to the network"
        abbr: "b"
        name: "bootstrap-node" .}: seq[string]

      bootstrapNodesFile* {.
        desc: "Specifies a line-delimited file of bootstrap Ethereum network addresses"
        defaultValue: ""
        name: "bootstrap-file" .}: InputFile

      listenAddress* {.
        desc: "Listening address for Logos Chain libp2p and Discovery v5 traffic"
        defaultValueDesc: "*"
        name: "listen-address" .}: Option[IpAddress]

      quicPort* {.
        desc: "UDP port for the QUIC (libp2p) listener"
        defaultValue: 5001
        name: "quic-port" .}: Port

      udpPort* {.
        desc: "UDP port for discv5 peer discovery"
        defaultValue: 5000
        name: "udp-port" .}: Port

      restPort* {.
        desc: "Listening HTTP port of the REST API server"
        defaultValue: 5050
        name: "rest-port" .}: Port

      discv5Enabled* {.
        desc: "Enable discv5 peer discovery (disable for isolated libp2p tests)"
        defaultValue: true
        name: "discv5" .}: bool

      maxPeers* {.
        desc: "The target number of peers to connect to"
        defaultValue: 160 # 5 (fanout) * 64 (subnets) / 2 (subs) for a heathy mesh
        name: "max-peers" .}: int

      hardMaxPeers* {.
        desc: "The maximum number of peers to connect to. Defaults to maxPeers * 1.5"
        name: "hard-max-peers" .}: Option[int]

      # TODO(logos-chain-networking): replace this eth-net NatConfig field with a
      # Logos-native public-address/reachability configuration type. Current UX
      # is confusing: setting a plain public IP via `extip:<IP>` hangs off the
      # `nat` flag, mixing NAT strategy selection with \"what address to
      # advertise\".
      nat* {.
        desc: "Specify method to use for determining public address. " &
              "Must be one of: any, none, upnp, pmp, extip:<IP>"
        defaultValue: NatConfig(hasExtIp: false, nat: NatAny)
        defaultValueDesc: "any"
        name: "nat" .}: NatConfig

      enrAutoUpdate* {.
        desc: "Discovery can automatically update its ENR with the IP address " &
              "and UDP port as seen by other nodes it communicates with. " &
              "This option allows to enable/disable this functionality"
        defaultValue: false
        name: "enr-auto-update" .}: bool

      externalBeaconApiUrl* {.
        desc: "External beacon API to use for syncing (on empty database)"
        name: "external-beacon-api-url" .}: Option[string]

      syncLightClient* {.
        desc: "Accelerate sync using light client"
        defaultValue: true
        name: "sync-light-client" .}: bool

      genesisStateUrl* {.
        desc: "URL for obtaining the genesis state of the network (for networks without a built-in genesis state)"
        name: "genesis-state-url" .}: Option[Uri]

      finalizedDepositTreeSnapshot* {.
        hidden
        name: "finalized-deposit-tree-snapshot" .}: Option[InputFile]

      nodeName* {.
        desc: "A name for this node that will appear in the logs. " &
              "If you set this to 'auto', a persistent automatically generated ID will be selected for each --data-dir folder"
        defaultValue: ""
        name: "node-name" .}: string

      metricsEnabled* {.
        desc: "Enable the metrics server"
        defaultValue: false
        name: "metrics" .}: bool

      metricsAddress* {.
        desc: "Listening address of the metrics server"
        defaultValue: defaultAdminListenAddress
        defaultValueDesc: $defaultAdminListenAddressDesc
        name: "metrics-address" .}: IpAddress

      metricsPort* {.
        desc: "Listening HTTP port of the metrics server"
        defaultValue: 8008
        name: "metrics-port" .}: Port

      deploymentSettingsFile* {.
        desc: "cfgsync deployment-settings YAML (network protocol IDs, mempool pubsub topic, cryptarchia gossipsub protocol)"
        defaultValue: InputFile(defaultDeploymentSettingsPath)
        name: "deployment-settings" .}: InputFile

      circuitsDir* {.
        desc: "Directory containing the logos-blockchain-circuits release bundle " &
              "(install via scripts/setup-logos-blockchain-circuits.sh)"
        defaultValue: defaultCircuitsDir()
        defaultValueDesc: "<platform data>/logos-blockchain-circuits/<version>"
        name: "circuits-dir" .}: InputDir

  AnyConf* = LBNodeConf

func parseCmdArg*(T: type Uri, input: string): T
                 {.raises: [ValueError].} =
  parseUri(input)

func completeCmdArg*(T: type Uri, input: string): seq[string] =
  return @[]

proc parseCmdArg*(T: type enr.Record, p: string): T {.raises: [ValueError].} =
  let res = enr.Record.fromURI(p)
  if res.isErr:
    raise newException(ValueError, "Invalid ENR:" & $res.error)

  res.value

func completeCmdArg*(T: type enr.Record, val: string): seq[string] =
  return @[]

proc secretsDir*[Conf](config: Conf): string =
  string config.secretsDirFlag.get(InputDir(config.dataDir / "secrets"))

func databaseDir*(dataDir: OutDir): string =
  dataDir / "db"

template databaseDir*(config: AnyConf): string =
  config.dataDir.databaseDir

func runAsService*(config: LBNodeConf): bool =
  config.runAsServiceFlag

template writeValue*(writer: var JsonWriter,
                     value: TypedInputFile|InputFile|InputDir|OutPath|OutDir|OutFile) =
  writer.writeValue(string value)

template raiseUnexpectedValue(r: var TomlReader, msg: string) =
  # TODO: We need to implement `raiseUnexpectedValue` for TOML,
  # so the correct line and column information can be included
  # in error messages:
  raise newException(SerializationError, msg)

proc readValue*(r: var TomlReader, val: var NatConfig)
               {.raises: [SerializationError].} =
  val = try: parseCmdArg(NatConfig, r.readValue(string))
        except ValueError, IOError:
          raise newException(SerializationError, getCurrentExceptionMsg())

proc formatIt*(v: Option[IpAddress]): string =
  if v.isSome():
    $v.get()
  else:
    "*"
