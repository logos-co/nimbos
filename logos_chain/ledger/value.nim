# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Checked arithmetic on `TokenValue`. The signed tx-running accumulator
## uses `Balance` in `balance.nim`.

{.push raises: [], gcsafe.}

import
  intops,
  results,
  ./types,
  ../core/mantle/primitives

func checkedAdd*(a, b: TokenValue): Result[TokenValue, LedgerError] =
  ## Returns `a + b`, or `BalanceOverflow` on overflow.
  let (res, didOverflow) = overflowingAdd(a, b)
  if didOverflow: err(BalanceOverflow) else: ok(res)

func checkedSub*(a, b: TokenValue): Result[TokenValue, LedgerError] =
  ## Returns `a - b`, or `BalanceOverflow` on underflow.
  let (res, didOverflow) = overflowingSub(a, b)
  if didOverflow: err(BalanceOverflow) else: ok(res)

{.pop.}
