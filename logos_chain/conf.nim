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
  eth/net/nat,
  eth/enr/enr,
  json_serialization, json_serialization/std/net as jsnet,
  chronos/transports/common,
  ./spec/datatypes/base,
  ./nimbus_binary_common

from std/os import dirExists, getHomeDir, `/`
from std/strutils import parseBiggestUInt, replace

export
  uri, nat, enr,
  enabledLogLevel,
  defs, parseCmdArg, completeCmdArg,
  confTomlDefs, confTomlNet, confTomlUri, jsnet,
  nimbus_binary_common

const
  # TODO: How should we select between IPv4 and IPv6
  # Maybe there should be a config option for this.
  defaultAdminListenAddress* = (static parseIpAddress("127.0.0.1"))
  defaultSigningNodeRequestTimeout* = 60
  defaultGasLimit* = 60_000_000
  defaultAdminListenAddressDesc* = $defaultAdminListenAddress

when defined(windows):
  {.pragma: windowsOnly.}
  {.pragma: posixOnly, hidden.}
else:
  {.pragma: windowsOnly, hidden.}
  {.pragma: posixOnly.}

type
  BNStartUpCmd* {.pure.} = enum
    beaconNode # match name in unified binary

  BeaconNodeConf* = object
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
      defaultValue: BNStartUpCmd.beaconNode .}: BNStartUpCmd

    of BNStartUpCmd.beaconNode:
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
        desc: "Listening address for the Ethereum LibP2P and Discovery v5 traffic"
        defaultValueDesc: "*"
        name: "listen-address" .}: Option[IpAddress]

      maxPeers* {.
        desc: "The target number of peers to connect to"
        defaultValue: 160 # 5 (fanout) * 64 (subnets) / 2 (subs) for a heathy mesh
        name: "max-peers" .}: int

      hardMaxPeers* {.
        desc: "The maximum number of peers to connect to. Defaults to maxPeers * 1.5"
        name: "hard-max-peers" .}: Option[int]

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

      finalizedCheckpointState* {.
        desc: "SSZ file specifying a recent finalized state"
        name: "finalized-checkpoint-state" .}: Option[InputFile]

      genesisState* {.
        desc: "SSZ file specifying the genesis state of the network (for networks without a built-in genesis state)"
        name: "genesis-state" .}: Option[InputFile]

      genesisStateUrl* {.
        desc: "URL for obtaining the genesis state of the network (for networks without a built-in genesis state)"
        name: "genesis-state-url" .}: Option[Uri]

      finalizedDepositTreeSnapshot* {.
        hidden
        name: "finalized-deposit-tree-snapshot" .}: Option[InputFile]

      finalizedCheckpointBlock* {.
        hidden
        desc: "SSZ file specifying a recent finalized block"
        name: "finalized-checkpoint-block" .}: Option[InputFile]

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

      statusBarEnabled* {.
        posixOnly
        desc: "Display a status bar at the bottom of the terminal screen"
        defaultValue: true
        name: "status-bar" .}: bool

      statusBarContents* {.
        posixOnly
        desc: "Textual template for the contents of the status bar"
        defaultValue: "peers: $connected_peers;" &
                      "finalized: $finalized_root:$finalized_epoch;" &
                      "head: $head_root:$head_epoch:$head_epoch_slot$next_consensus_fork;" &
                      "time: $epoch:$epoch_slot ($slot);" &
                      "sync: $sync_status|" &
                      "ETH: $attached_validators_balance"
        defaultValueDesc: ""
        name: "status-bar-contents" .}: string

      rpcEnabled* {.
        # Deprecated > 1.7.0
        hidden
        desc: "Deprecated for removal"
        name: "rpc" .}: Option[bool]

      rpcPort* {.
        # Deprecated > 1.7.0
        hidden
        desc: "Deprecated for removal"
        name: "rpc-port" .}: Option[Port]

      rpcAddress* {.
        # Deprecated > 1.7.0
        hidden
        desc: "Deprecated for removal"
        name: "rpc-address" .}: Option[IpAddress]

      restEnabled* {.
        desc: "Enable the REST server"
        defaultValue: false
        name: "rest" .}: bool

      restAddress* {.
        desc: "Listening address of the REST server"
        defaultValue: defaultAdminListenAddress
        defaultValueDesc: $defaultAdminListenAddressDesc
        name: "rest-address" .}: IpAddress

      restAllowedOrigin* {.
        desc: "Limit the access to the REST API to a particular hostname " &
              "(for CORS-enabled clients such as browsers)"
        name: "rest-allow-origin" .}: Option[string]

      restCacheSize* {.
        defaultValue: 3
        desc: "The maximum number of recently accessed states that are kept in " &
              "memory. Speeds up requests obtaining information for consecutive " &
              "slots or epochs."
        name: "rest-statecache-size" .}: Natural

      restCacheTtl* {.
        defaultValue: 60
        desc: "The number of seconds to keep recently accessed states in memory"
        name: "rest-statecache-ttl" .}: Natural

      restRequestTimeout* {.
        defaultValue: 0
        defaultValueDesc: "infinite"
        desc: "The number of seconds to wait until complete REST request " &
              "will be received"
        name: "rest-request-timeout" .}: Natural

      restMaxRequestBodySize* {.
        defaultValue: 16_384
        desc: "Maximum size of REST request body (kilobytes)"
        name: "rest-max-body-size" .}: Natural

      restMaxRequestHeadersSize* {.
        defaultValue: 128
        desc: "Maximum size of REST request headers (kilobytes)"
        name: "rest-max-headers-size" .}: Natural
        ## NOTE: If you going to adjust this value please check value
        ## ``ClientMaximumValidatorIds`` and comments in
        ## `spec/eth2_apis/rest_types.nim`. This values depend on each other.

      keymanagerEnabled* {.
        desc: "Enable the REST keymanager API"
        defaultValue: false
        name: "keymanager" .}: bool

      keymanagerAddress* {.
        desc: "Listening port for the REST keymanager API"
        defaultValue: defaultAdminListenAddress
        defaultValueDesc: $defaultAdminListenAddressDesc
        name: "keymanager-address" .}: IpAddress

      keymanagerAllowedOrigin* {.
        desc: "Limit the access to the Keymanager API to a particular hostname " &
              "(for CORS-enabled clients such as browsers)"
        name: "keymanager-allow-origin" .}: Option[string]

      keymanagerTokenFile* {.
        desc: "A file specifying the authorization token required for accessing the keymanager API"
        name: "keymanager-token-file" .}: Option[InputFile]

      lightClientDataServe* {.
        desc: "Serve data for enabling light clients to stay in sync with the network"
        defaultValue: true
        name: "light-client-data-serve" .}: bool

      inProcessValidators* {.
        hidden
        desc: "Deprecated for removal"
        name: "in-process-validators" .}: Option[bool]

      discv5Enabled* {.
        desc: "Enable Discovery v5"
        defaultValue: true
        name: "discv5" .}: bool

      dumpEnabled* {.
        desc: "Write SSZ dumps of blocks and states to data dir"
        defaultValue: false
        name: "dump" .}: bool

      directPeers* {.
        desc: "The list of privileged, secure and known peers to connect and maintain the connection to. This requires a not random netkey-file. In the multiaddress format like: /ip4/<address>/tcp/<port>/p2p/<peerId-public-key>, or enr format (enr:-xx). Peering agreements are established out of band and must be reciprocal"
        name: "direct-peer" .}: seq[string]

      doppelgangerDetection* {.
        desc: "If enabled, the beacon node prudently listens for 2 epochs for attestations from a validator with the same index (a doppelganger), before sending an attestation itself. This protects against slashing (due to double-voting) but means you will miss two attestations when restarting."
        defaultValue: true
        name: "doppelganger-detection" .}: bool

  AnyConf* = BeaconNodeConf

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

func runAsService*(config: BeaconNodeConf): bool =
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
        except CatchableError as err:
          raise newException(SerializationError, err.msg)

proc formatIt*(v: Option[IpAddress]): string =
  if v.isSome():
    $v.get()
  else:
    "*"
