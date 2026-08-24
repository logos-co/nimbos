# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Gas units, per-operation execution gas, and protocol gas constants.
## Spec: [Bedrock v1.1 — Mantle Specification v1.10.0 — Gas Determination](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md#gas-determination)

{.push raises: [], gcsafe.}

import
  results,
  ./operations

type
  Gas* = uint64        ## execution: 1 gas = 1,000 CPU cycles; storage: 1 gas = 1 byte
  GasPrice* = uint64   ## LGO per gas unit
  GasCost* = uint64    ## LGO

  GasPrices* = object
    executionBaseFee*: GasPrice
    storageGasPrice*: GasPrice

const
  # Spec: bedrock-v1.1-mantle-specification.md "Gas Determination" table.
  # Names verbatim from the spec.
  EXECUTION_TRANSFER_GAS = Gas(590)
  EXECUTION_CHANNEL_INSCRIBE_GAS = Gas(56)
  EXECUTION_CHANNEL_CONFIG_GAS = Gas(56)
  EXECUTION_CHANNEL_DEPOSIT_GAS = Gas(590)
  EXECUTION_CHANNEL_WITHDRAW_GAS = Gas(56)
  EXECUTION_CHANNEL_TRANSFER_GAS = Gas(56)
  EXECUTION_SDP_DECLARE_GAS = Gas(646)
  EXECUTION_SDP_WITHDRAW_GAS = Gas(590)
  EXECUTION_SDP_ACTIVE_GAS = Gas(590)
  EXECUTION_LEADER_CLAIM_GAS = Gas(580)

  # execution-market.md G_max: 3,200,000 execution gas (1s at 80% of a
  # min-spec CPU) minus the 6,540 reserved for batch-verification init.
  # Diverges from the reference implementation, which uses 3_193_360.
  MAX_EXECUTION_GAS_PER_BLOCK* = Gas(3_193_460)

func checkedAdd*(a, b: Gas): Opt[Gas] =
  if a > uint64.high - b: Opt.none(Gas) else: Opt.some(a + b)

func checkedSub*(a, b: Gas): Opt[Gas] =
  if a < b: Opt.none(Gas) else: Opt.some(a - b)

func checkedMul*(a: Gas, b: GasPrice): Opt[GasCost] =
  if a != 0 and b > uint64.high div a: Opt.none(GasCost) else: Opt.some(a * b)

func execution_gas*(op: Op, multisigThreshold: uint16): Gas =
  ## Execution gas for one operation. `multisigThreshold` scales the channel
  ## config/withdraw/transfer cost; ignored otherwise.
  # One 56-gas unit per Ed25519 verification, per the spec's Gas Determination.
  case op.payload.kind
  of Transfer: EXECUTION_TRANSFER_GAS
  of ChannelInscribe: EXECUTION_CHANNEL_INSCRIBE_GAS
  of ChannelConfig: EXECUTION_CHANNEL_CONFIG_GAS * Gas(multisigThreshold)
  of ChannelDeposit: EXECUTION_CHANNEL_DEPOSIT_GAS
  of ChannelWithdraw: EXECUTION_CHANNEL_WITHDRAW_GAS * Gas(multisigThreshold)
  of ChannelTransfer: EXECUTION_CHANNEL_TRANSFER_GAS * Gas(multisigThreshold)
  of SdpDeclare: EXECUTION_SDP_DECLARE_GAS
  of SdpWithdraw: EXECUTION_SDP_WITHDRAW_GAS
  of SdpActive: EXECUTION_SDP_ACTIVE_GAS
  of LeaderClaim: EXECUTION_LEADER_CLAIM_GAS

{.pop.}
