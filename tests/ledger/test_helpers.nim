# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Shared fixtures for the consensus test suites.

{.push raises: [], gcsafe.}

import
  std/sequtils,
  stew/endians2,
  libp2p/crypto/ed25519/ed25519,
  ../../logos_chain/core/mantle/[primitives, proofs, utxo],
  ../../logos_chain/ledger/[mantle_state, stake_inference, types],
  ../../logos_chain/zk/poseidon2/hasher

from ../../logos_chain/core/crypto/types import ZkPublicKey
from ../../logos_chain/ledger/ledger import fromGenesis, LedgerState
from ./sdp/test_helpers import testSdpRegistry
from ../testutil import testValidGenesisTx

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
    learningRateFixed: fixedPoint(NonNegativeRatio(num: 1, den: 1)),
    faucetPk: Opt.none(ZkPublicKey))

func fe*(n: uint64): FieldElement =
  ## Small-integer field element for test vectors.
  frFromBytesLE(n.toBytesLE).expect("8 bytes < order")

func seedChannelNotes*(
    owners: openArray[tuple[note: Utxo, channel: ChannelId]]
): ChannelNotes =
  ## Registry with each note owned by its paired channel.
  var notes = ChannelNotes.init()
  for (note, channel) in owners:
    notes = notes.registerChannelNote(note.id, channel).expect("fresh note")
  notes

proc seedMantle*(
    cid: ChannelId,
    keys: openArray[Ed25519PublicKey],
    owned: openArray[Utxo] = [],
    transferThreshold = TransferThreshold(2),
): MantleState =
  ## One channel under `cid` with `keys` accredited and `owned` as its notes.
  MantleState(
    channels: HashTrieMap[ChannelId, ChannelState].init().insert(
      cid,
      ChannelState(
        accreditedKeys: @keys,
        configurationThreshold: 2,
        transferThreshold: transferThreshold,
      ),
    ),
    channelNotes: seedChannelNotes(owned.mapIt((note: it, channel: cid))),
  )

func twoOfTwo*(kp1, kp2: EdKeyPair, txHash: Hash32): ChannelMultiSigProof =
  ## 2-of-2 multisig proof over `txHash` from keys at indexes 0 and 1.
  ChannelMultiSigProof(
    signatures: @[sign(kp1.seckey, txHash), sign(kp2.seckey, txHash)],
    indexes: @[ChannelKeyIndex(0), ChannelKeyIndex(1)],
  )

var defaultGenesisLedgerStateCache: LedgerState
var hasDefaultGenesisLedgerStateCache = false

proc testGenesisLedgerState*(): LedgerState =
  ## Cached pristine LedgerState at genesis, returned by copy (safe for local mutation).
  {.gcsafe.}:
    if not hasDefaultGenesisLedgerStateCache:
      defaultGenesisLedgerStateCache = LedgerState.fromGenesis(
        testValidGenesisTx(), default(FieldElement), testSdpRegistry(), testLedgerConfig
      ).expect("genesis state")
      hasDefaultGenesisLedgerStateCache = true
    defaultGenesisLedgerStateCache

{.pop.}
