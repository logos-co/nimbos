# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Shared fixtures for the consensus test suites.

{.push raises: [], gcsafe.}

import
  stew/endians2,
  ../../logos_chain/time/clock,
  ../../logos_chain/ledger/types,
  ../../logos_chain/zk/poseidon2/hasher

from ../../logos_chain/core/crypto/types import ZkPublicKey

const
  testSchedule* = EpochSchedule(
    basePeriodLength: 10, # k = 5, f = 1/2
    stakeDistributionStabilization: 3,
    nonceBuffer: 3,
    nonceStabilization: 4)
  # f = 1/10 keeps the lottery-constants lookup satisfied (standalone entry);
  # no faucet, so total stake is the plain UTXO sum.
  testLedgerConfig* = LedgerConfig(
    epochSchedule: testSchedule,
    slotActivationCoeff: NonNegativeRatio(num: 1, den: 10),
    stakeInferenceLearningRate: NonNegativeRatio(num: 1, den: 1),
    faucetPk: Opt.none(ZkPublicKey))

func fe*(n: uint64): FieldElement =
  ## Small-integer field element for test vectors.
  frFromBytesLE(n.toBytesLE).expect("8 bytes < order")

{.pop.}
