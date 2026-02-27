# Nim dummy/stub API for logos-blockchain C FFI export
#
# This file provides dummy implementations of all functions from the
# logos-blockchain C API. These functions are exported to C FFI and can be
# compiled as a C library. All functions return empty/default values.
#
# To compile as a C library:
#   nim c --skipUserCfg:on --skipProjCfg:on --skipParentCfg:on --app:staticlib --out:liblogos_blockchain.a logos_c_bindings.nim
#
# Note: All functions that take pointers are unsafe. The caller must ensure
# all pointers are valid and properly aligned.

type
  OperationStatus* = enum
    Ok = 0
    NotFound = 1
    NullPointer = 2
    RelayError = 3
    ChannelSendError = 4
    ChannelReceiveError = 5
    ServiceError = 6
    RuntimeError = 7
    DynError = 8
    InitializationError = 9
    StopError = 10
    ConfigurationError = 11

  DeploymentType* = enum
    WellKnown = 0
    Custom = 1

  WellKnownDeployment* = enum
    Devnet = 0

  State* = enum
    Bootstrapping = 0
    Online = 1

  Hash* = array[32, uint8]
  HeaderId* = Hash
  Value* = uint64

  Deployment* = object
    deployment_type: DeploymentType
    well_known_deployment: WellKnownDeployment
    custom_deployment_config_path: cstring

  GenerateConfigArgs* = object
    initial_peers: ptr UncheckedArray[cstring]
    initial_peers_count: ptr uint32
    output: cstring
    net_port: ptr uint16
    blend_port: ptr uint16
    http_addr: cstring
    external_address: cstring
    no_public_ip_check: ptr bool
    deployment: ptr Deployment
    state_path: cstring

  CryptarchiaInfo* = object
    lib: HeaderId
    tip: HeaderId
    slot: uint64
    height: uint64
    mode: State

  CryptarchiaInfoResult* = object
    value: ptr CryptarchiaInfo
    error: OperationStatus

  LogosBlockchainNode* = object
    overwatch: pointer
    runtime: pointer

  InitializedLogosBlockchainNodeResult* = object
    value: ptr LogosBlockchainNode
    error: OperationStatus

  CCallback_c_char* = proc(data: cstring) {.cdecl.}

  KnownAddresses* = object
    addresses: ptr UncheckedArray[ptr uint8]
    len: uint

  KnownAddressesResult* = object
    value: KnownAddresses
    error: OperationStatus

  BalanceResult* = object
    value: Value
    error: OperationStatus

  TransferFundsResult* = object
    value: Hash
    error: OperationStatus

  TransferFundsArguments* = object
    optional_tip: ptr HeaderId
    change_public_key: ptr uint8
    funding_public_keys: ptr UncheckedArray[ptr uint8]
    funding_public_keys_len: uint
    recipient_public_key: ptr uint8
    amount: uint64

proc generate_user_config*(
    args: GenerateConfigArgs
): OperationStatus {.exportc, cdecl.} =
  result = Ok

proc get_cryptarchia_info*(
    node: ptr LogosBlockchainNode
): CryptarchiaInfoResult {.exportc, cdecl.} =
  result.value = nil
  result.error = Ok

proc free_cryptarchia_info*(pointer: ptr CryptarchiaInfo) {.exportc, cdecl.} =
  discard

proc start_lb_node*(
    config_path: cstring, deployment: cstring
): InitializedLogosBlockchainNodeResult {.exportc, cdecl.} =
  result.value = nil
  result.error = Ok

proc stop_node*(node: ptr LogosBlockchainNode): OperationStatus {.exportc, cdecl.} =
  result = Ok

proc free_cstring*(blockPtr: cstring) {.exportc, cdecl.} =
  discard

proc subscribe_to_new_blocks*(
    node: ptr LogosBlockchainNode, callback_per_block: CCallback_c_char
) {.exportc, cdecl.} =
  discard

proc get_known_addresses*(
    node: ptr LogosBlockchainNode
): KnownAddressesResult {.exportc, cdecl.} =
  result.value.addresses = nil
  result.value.len = 0
  result.error = Ok

proc free_known_addresses*(addresses: KnownAddresses) {.exportc, cdecl.} =
  discard

proc get_balance*(
    node: ptr LogosBlockchainNode, wallet_address: ptr uint8, optional_tip: ptr HeaderId
): BalanceResult {.exportc, cdecl.} =
  result.value = 0
  result.error = Ok

proc transfer_funds*(
    node: ptr LogosBlockchainNode, arguments: ptr TransferFundsArguments
): TransferFundsResult {.exportc, cdecl.} =
  result.value = default(Hash)
  result.error = Ok

proc free_transfer_funds*(pointer: ptr Hash) {.exportc, cdecl.} =
  discard

proc is_ok*(self: ptr OperationStatus): bool {.exportc, cdecl.} =
  if self == nil:
    return false
  result = self[] == Ok

proc is_error*(self: ptr OperationStatus): bool {.exportc, cdecl.} =
  result = not is_ok(self)
