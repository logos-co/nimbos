# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  ../../logos_chain/ledger/epoch_state,
  ./test_helpers

const mainnetF = NonNegativeRatio(num: 1, den: 30)

suite "ledger/epoch_state":
  test "genesis ctor seeds nonce, root, stake and lottery":
    let state = genesisEpochState(0, fe(7), fe(9), 1000, mainnetF).expect(
      "supported f")
    check:
      state.epoch == 0
      state.nonce == fe(7)
      state.agedUtxoRoot == fe(9)
      state.totalStake == 1000
      state.lottery0 != default(FieldElement)
      state.lottery1 != default(FieldElement)

  test "genesis ctor rejects an unsupported f":
    check genesisEpochState(
      0, fe(7), fe(9), 1000, NonNegativeRatio(num: 2, den: 30)).isErr

  test "nonce chain is deterministic and input-sensitive":
    let base = accumulateNonce(fe(1), fe(2), 5)
    check:
      base == accumulateNonce(fe(1), fe(2), 5)
      base != accumulateNonce(fe(1), fe(2), 6) # slot matters
      base != accumulateNonce(fe(1), fe(3), 5) # contribution matters
      base != accumulateNonce(fe(4), fe(2), 5) # previous nonce matters
      base != default(FieldElement)

  test "a ten-step chain differs from any prefix":
    var
      nonce = fe(0)
      seen: seq[FieldElement]
    for slot in 1'u64 .. 10'u64:
      nonce = accumulateNonce(nonce, fe(slot), slot)
      check nonce notin seen
      seen.add nonce

  test "chase-and-freeze against the nonce snapshot":
    # Epoch 2: nonce snapshot at slot 160, stake snapshot at slot 100.
    var state = genesisEpochState(0, fe(1), fe(1), 1000, mainnetF).expect(
      "supported f")
    state.epoch = 2
    let
      chasedEarly = state.updateFromLedger(fe(11), fe(22), 99, testSchedule)
      chasedMid = state.updateFromLedger(fe(11), fe(22), 159, testSchedule)
      frozen = state.updateFromLedger(fe(11), fe(22), 160, testSchedule)
    check:
      chasedEarly.nonce == fe(11) # before both snapshots: chase both
      chasedEarly.agedUtxoRoot == fe(22)
      chasedMid.nonce == fe(11) # stake frozen, nonce still chasing
      chasedMid.agedUtxoRoot == fe(1)
      frozen.nonce == fe(1) # at/after the snapshot slot: both frozen
      frozen.agedUtxoRoot == fe(1)

  test "epoch 1 aged root never chases (snapshot is slot 0)":
    var state = genesisEpochState(1, fe(1), fe(9), 1000, mainnetF).expect(
      "supported f")
    let updated = state.updateFromLedger(fe(11), fe(22), 5, testSchedule)
    check:
      updated.agedUtxoRoot == fe(9) # genesis root stays
      updated.nonce == fe(11) # nonce chases until slot 60

{.pop.}
