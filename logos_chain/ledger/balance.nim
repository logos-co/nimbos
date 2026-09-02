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

from ../core/mantle/primitives import Value

export stint

type
  Balance* = Int128

const
  DefaultBalance* = default(Balance)

func zero*(_: typedesc[Balance]): Balance {.inline.} =
  # `i128(0)` instantiates a buggy `stint(SignedInt, bits)` path in
  # `vendor/nim-stint/stint/io.nim:73` (`result.negate` parses as field
  # lookup, not the proc). `default` sidesteps that path.
  DefaultBalance

# Stint exposes no public checked arithmetic — only wrapping `+` / `-`. These
# helpers do explicit MIN/MAX headroom checks for arbitrary signed operands.

func checkedAdd*(a, b: Balance): Result[Balance, LedgerError] =
  ## Returns `a + b`, or `BalanceOutOfRange` when the result falls outside
  ## `[Balance.low, Balance.high]`.
  if b > Balance.zero and a > (Balance.high - b):
    err(BalanceOutOfRange)
  elif b < Balance.zero and a < (Balance.low - b):
    err(BalanceOutOfRange)
  else:
    ok(a + b)

func covers*(balance: Balance, cost: uint64): bool =
  ## True when `balance` can pay `cost`.
  balance >= cost.to(Balance)

func checked_uint64*(b: Balance): Result[Value, LedgerError] =
  ## Checked narrowing to `Value`; `BalanceOutOfRange` outside `[0, uint64.high]`.
  # An unrepresentable result invalidates the tx rather than wrapping. The
  # lower bound also keeps stint's signed `truncate` (via `abs`) off negatives.
  if b < Balance.zero or b > static(uint64.high.to(Balance)):
    err(BalanceOutOfRange)
  else:
    ok(b.truncate(uint64))

func checkedSub*(a, b: Balance): Result[Balance, LedgerError] =
  ## Returns `a - b`, or `BalanceOutOfRange` when the result falls outside
  ## `[Balance.low, Balance.high]`.
  if b < Balance.zero and a > (Balance.high + b):
    err(BalanceOutOfRange)
  elif b > Balance.zero and a < (Balance.low + b):
    err(BalanceOutOfRange)
  else:
    ok(a - b)

{.pop.}
