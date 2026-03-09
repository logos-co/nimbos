# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
#
## C library bindings for the Logos blockchain node (FFI).
##
## From the repo root, use the Makefile targets:
##   make logos-lib       - build static library (liblogos_blockchain.a)
##   make logos-headers   - generate C header (logos_c_bindings.h)
##   make logos-bindings  - build both library and header

{.push raises: [], gcsafe.}

type
  OperationStatus* {.pure, exportc.} = enum
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

  DeploymentType* {.pure, exportc.} = enum
    WellKnown = 0
    Custom = 1

  WellKnownDeployment* {.pure, exportc.} = enum
    Devnet = 0

  State* {.pure, exportc.} = enum
    Bootstrapping = 0
    Online = 1

  LogosDigest* {.exportc.} = array[32, byte]
  HeaderId* {.exportc.} = LogosDigest
  Value* {.exportc.} = uint64

  Deployment* {.exportc.} = object
    deployment_type: DeploymentType
    well_known_deployment: WellKnownDeployment
    custom_deployment_config_path: cstring

  GenerateConfigArgs* {.exportc.} = object
    initial_peers*: ptr UncheckedArray[cstring]
    initial_peers_count*: ptr uint32           
    output*: cstring                           
    net_port*: ptr uint16                      
    blend_port*: ptr uint16                    
    http_addr*: cstring                        
    external_address*: cstring                 
    no_public_ip_check*: ptr bool              
    deployment*: ptr Deployment                
    state_path*: cstring                       

  CryptarchiaInfo* {.exportc.} = object
    lib: HeaderId
    tip: HeaderId
    slot: uint64
    height: uint64
    mode: State

  CryptarchiaInfoResult* {.exportc.} = object
    value: ptr CryptarchiaInfo
    error: OperationStatus

  LogosBlockchainNode* {.exportc.} = object
    overwatch: pointer
    runtime: pointer

  InitializedLogosBlockchainNodeResult* {.exportc.} = object
    value: ptr LogosBlockchainNode
    error: OperationStatus

  CCallback_c_char* = proc(data: cstring) {.cdecl.}

  KnownAddresses* {.exportc.} = object
    addresses: ptr UncheckedArray[ptr byte]
    len: uint

  KnownAddressesResult* {.exportc.} = object
    value: KnownAddresses
    error: OperationStatus

  BalanceResult* {.exportc.} = object
    value: Value
    error: OperationStatus

  TransferFundsResult* {.exportc.} = object
    value: LogosDigest
    error: OperationStatus

  TransferFundsArguments* {.exportc.} = object
    optional_tip: ptr HeaderId
    change_public_key: ptr byte
    funding_public_keys: ptr UncheckedArray[ptr byte]
    funding_public_keys_len: uint
    recipient_public_key: ptr byte
    amount: uint64

proc generate_user_config*(
    args: GenerateConfigArgs
): OperationStatus {.exportc, cdecl.} =
  Ok

proc get_cryptarchia_info*(
    node: ptr LogosBlockchainNode
): CryptarchiaInfoResult {.exportc, cdecl.} =
  CryptarchiaInfoResult(value: nil, error: Ok)

proc free_cryptarchia_info*(pointer: ptr CryptarchiaInfo) {.exportc, cdecl.} =
  discard

proc start_lb_node*(
    config_path: cstring, deployment: cstring
): InitializedLogosBlockchainNodeResult {.exportc, cdecl.} =
  InitializedLogosBlockchainNodeResult(value: nil, error: Ok)

proc stop_node*(node: ptr LogosBlockchainNode): OperationStatus {.exportc, cdecl.} =
  Ok

proc free_cstring*(blockPtr: cstring) {.exportc, cdecl.} =
  discard

proc subscribe_to_new_blocks*(
    node: ptr LogosBlockchainNode, callback_per_block: CCallback_c_char
) {.exportc, cdecl.} =
  discard

proc get_known_addresses*(
    node: ptr LogosBlockchainNode
): KnownAddressesResult {.exportc, cdecl.} =
  KnownAddressesResult(value: KnownAddresses(addresses: nil, len: 0), error: Ok)

proc free_known_addresses*(addresses: KnownAddresses) {.exportc, cdecl.} =
  discard

proc get_balance*(
    node: ptr LogosBlockchainNode, wallet_address: ptr byte, optional_tip: ptr HeaderId
): BalanceResult {.exportc, cdecl.} =
  BalanceResult(value: 0, error: Ok)

proc transfer_funds*(
    node: ptr LogosBlockchainNode, arguments: ptr TransferFundsArguments
): TransferFundsResult {.exportc, cdecl.} =
  TransferFundsResult(value: default(LogosDigest), error: Ok)

proc free_transfer_funds*(pointer: ptr LogosDigest) {.exportc, cdecl.} =
  discard

func is_ok*(self: ptr OperationStatus): bool {.exportc, cdecl.} =
  if self == nil:
    return false
  self[] == Ok

func is_error*(self: ptr OperationStatus): bool {.exportc, cdecl.} =
  not is_ok(self)

{.pop.}
