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

export results

type
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

{.pop.}
