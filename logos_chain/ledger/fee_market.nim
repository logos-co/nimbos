# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Fee-market consensus state: execution base fee and storage gas price.
## Spec: [Execution Market](https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/execution-market.md),
## [Storage Markets](https://github.com/logos-co/logos-lips/blob/709cf7f1662affa6efa094e2fb066e9b530b5aaa/docs/blockchain/raw/storage-markets.md)

{.push raises: [], gcsafe.}

import
  stint,
  ../core/mantle/gas

type
  FeeMarket* = object
    ## Fee-market consensus state, one copy per ledger state.
    averageExecutionGas*: Gas ## EMA of per-block execution gas
    executionBaseFee*: GasPrice ## updated every block
    storageGasEma*: Gas ## EMA of per-epoch storage gas
    storageGasPrice*: GasPrice ## updated every epoch rotation
    storageGasConsumedInEpoch*: Gas ## running counter, reset at rotation

const
  # execution-market.md:180-193, names from the spec's reference code
  # (EXECUTION_ prefix disambiguates from the storage market's constants).
  EXECUTION_EMA_DENOMINATOR = 10'u64
  EXECUTION_EMA_PREV_WEIGHT = 9'u64
  # 7 * G_target and 8 * G_target for G_target = 1,596,730 = G_max/2
  # (execution-market.md:97-98). Diverges from the reference implementation
  # and the spec's own reference code (:183-184), which embed 11_176_760 /
  # 12_773_440 (G_target 1,596,680, half the stale G_max); upstream is
  # updating the spec to these values.
  EXECUTION_BASE_FEE_NUMERATOR = 11_177_110'u64
  EXECUTION_BASE_FEE_DENOMINATOR = 12_773_840'u64

  # storage-markets.md:194-206
  STORAGE_EMA_DENOMINATOR = 2'u64
  STORAGE_CLAMP_DENOMINATOR = 8'u64
  STORAGE_CLAMP_DOWN_NUMERATOR = 7'u64
  STORAGE_CLAMP_UP_NUMERATOR = 9'u64

  # Both markets open at price 1 (execution-market.md:94, storage-markets.md:104).
  GENESIS_EXECUTION_BASE_FEE = GasPrice(1)
  GENESIS_STORAGE_GAS_PRICE = GasPrice(1)

func init*(_: typedesc[FeeMarket]): FeeMarket =
  FeeMarket(
    executionBaseFee: GENESIS_EXECUTION_BASE_FEE,
    storageGasPrice: GENESIS_STORAGE_GAS_PRICE)

func gasPrices*(m: FeeMarket): GasPrices =
  GasPrices(
    executionBaseFee: m.executionBaseFee,
    storageGasPrice: m.storageGasPrice)

func update_g_avg_num*(prev_g_avg_num: Gas, block_gas_used: Gas): Gas =
  ## Per-block execution-gas EMA step (execution-market.md reference code).
  let numerator = u128(block_gas_used) +
    u128(EXECUTION_EMA_PREV_WEIGHT) * u128(prev_g_avg_num)
  (numerator div u128(EXECUTION_EMA_DENOMINATOR)).truncate(uint64)

func update_base_fee*(base_fee: GasPrice, g_avg: Gas): GasPrice =
  ## Per-block base-fee update from the current gas EMA.
  let numerator = u128(base_fee) *
    (u128(EXECUTION_BASE_FEE_NUMERATOR) + u128(g_avg))
  (numerator div u128(EXECUTION_BASE_FEE_DENOMINATOR)).truncate(uint64)

func update_usage*(total_gas_consumed, previous_usage: Gas): Gas =
  ## Per-epoch storage-gas EMA step (storage-markets.md reference code).
  (u128(total_gas_consumed) + u128(previous_usage))
    .div(u128(STORAGE_EMA_DENOMINATOR)).truncate(uint64)

func update_storage_price*(
    prev_price: GasPrice, total_gas_consumed, usage: Gas): GasPrice =
  ## Per-epoch price update; `usage` is the already-updated EMA.
  # Without this guard the clamp-down branch fires on every empty epoch and
  # floors the genesis price to zero.
  if usage == 0:
    return prev_price
  let
    comparator = u128(STORAGE_CLAMP_DENOMINATOR) * u128(total_gas_consumed)
    price = u128(prev_price)
    newPrice =
      if comparator <= u128(STORAGE_CLAMP_DOWN_NUMERATOR) * u128(usage):
        price * u128(STORAGE_CLAMP_DOWN_NUMERATOR) div
          u128(STORAGE_CLAMP_DENOMINATOR)
      elif comparator >= u128(STORAGE_CLAMP_UP_NUMERATOR) * u128(usage):
        price * u128(STORAGE_CLAMP_UP_NUMERATOR) div
          u128(STORAGE_CLAMP_DENOMINATOR)
      else:
        price * u128(total_gas_consumed) div u128(usage)
  newPrice.truncate(uint64)

func updateExecutionMarket*(m: FeeMarket, blockExecutionGas: Gas): FeeMarket =
  ## Applies the per-block execution-market step to the state.
  var next = m
  next.averageExecutionGas = update_g_avg_num(
    m.averageExecutionGas, blockExecutionGas)
  next.executionBaseFee = update_base_fee(
    m.executionBaseFee, next.averageExecutionGas)
  next

func updateStorageMarket*(m: FeeMarket): FeeMarket =
  ## Applies the per-epoch storage-market step; consumes and resets the
  ## epoch usage counter.
  var next = m
  next.storageGasEma = update_usage(
    m.storageGasConsumedInEpoch, m.storageGasEma)
  next.storageGasPrice = update_storage_price(
    m.storageGasPrice, m.storageGasConsumedInEpoch, next.storageGasEma)
  next.storageGasConsumedInEpoch = 0
  next

{.pop.}
