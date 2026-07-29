# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Tx-running ledger balance arithmetic. Internal to the ledger module.

{.push raises: [], gcsafe.}

import results, stint

import ./types

export stint

type
  Balance* = Int128

func zero*(_: typedesc[Balance]): Balance =
  # `i128(0)` instantiates a buggy `stint(SignedInt, bits)` path in
  # `vendor/nim-stint/stint/io.nim:73` (`result.negate` parses as field
  # lookup, not the proc). `default` sidesteps that path.
  default(Balance)

# Stint exposes no public checked arithmetic — only wrapping `+` / `-`. These
# helpers do explicit MIN/MAX headroom checks for arbitrary signed operands.

func checkedAdd*(a, b: Balance): Result[Balance, LedgerError] =
  ## Returns `a + b`, or `BalanceOverflow` when the result falls outside
  ## `[Balance.low, Balance.high]`.
  if b > Balance.zero and a > (Balance.high - b):
    err(BalanceOverflow)
  elif b < Balance.zero and a < (Balance.low - b):
    err(BalanceOverflow)
  else:
    ok(a + b)

func covers*(balance: Balance, cost: uint64): bool =
  ## True when `balance` can pay `cost`.
  balance >= cost.to(Balance)

func checkedSub*(a, b: Balance): Result[Balance, LedgerError] =
  ## Returns `a - b`, or `BalanceOverflow` when the result falls outside
  ## `[Balance.low, Balance.high]`.
  if b < Balance.zero and a > (Balance.high + b):
    err(BalanceOverflow)
  elif b > Balance.zero and a < (Balance.low + b):
    err(BalanceOverflow)
  else:
    ok(a - b)

{.pop.}
