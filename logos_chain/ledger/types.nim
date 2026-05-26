# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Ledger module common types.
##
## `LedgerError` is a flat `{.pure.}` enum: coarse rejection categories, no
## carried payload — per-rejection detail goes to logs at the rejection site.

{.push raises: [], gcsafe.}

import results
import stint

export results, stint

type
  Balance* = Int128
    ## Tx-running ledger balance (signed, 128-bit). Intermediate sums may
    ## go negative on rewards or exceed u64 on multi-input transfers.

  LedgerError* {.pure.} = enum
    ## Consensus rejection categories. New variants land with the modules
    ## that emit them.
    ParentNotFound ## prepareUpdate's parent_id is not in the map
    InvalidNote ## input NoteId not in UtxoStore
    LockedNote ## input NoteId is in LockedNotes
    ZeroValueNote ## output Note has value == 0
    InvalidProof ## ZK multi-sig or leader-proof verify failed
    BalanceOverflow ## Int128 add/sub overflowed during balance math
    UnsupportedOp ## Op kind not yet wired in this ledger version
    UnbalancedTransaction ## inputs - outputs > fees
    InsufficientBalance ## inputs - outputs < fees

  LedgerConfig* = object
    ## Chain configuration. Currently empty — fields land with the modules
    ## that need them (epoch, lottery, SDP, gas).

func zero*(_: typedesc[Balance]): Balance =
  # `i128(0)` instantiates a buggy `stint(SignedInt, bits)` path in
  # `vendor/nim-stint/stint/io.nim:73` (`result.negate` parses as field
  # lookup, not the proc). `default` sidesteps that path.
  default(Balance)

# Stint exposes no public checked arithmetic — only wrapping `+` / `-`. These
# helpers do explicit MIN/MAX headroom checks for arbitrary signed operands.

func checkedAdd*(a, b: Balance): Result[Balance, LedgerError] =
  ## Saturates at `BalanceOverflow` when `a + b` falls outside
  ## `[Balance.low, Balance.high]`.
  if b > Balance.zero and a > (Balance.high - b):
    err(BalanceOverflow)
  elif b < Balance.zero and a < (Balance.low - b):
    err(BalanceOverflow)
  else:
    ok(a + b)

func checkedSub*(a, b: Balance): Result[Balance, LedgerError] =
  ## Saturates at `BalanceOverflow` when `a - b` falls outside
  ## `[Balance.low, Balance.high]`.
  if b < Balance.zero and a > (Balance.high + b):
    err(BalanceOverflow)
  elif b > Balance.zero and a < (Balance.low + b):
    err(BalanceOverflow)
  else:
    ok(a - b)

{.pop.}
