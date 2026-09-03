# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Service reward minting: deterministic reward-note construction from a
## payout map, one note per rewarded zk_id.
## Spec: [Service Reward Distribution](https://github.com/logos-co/logos-lips/blob/a2a85cbe444e9727ae7f42b2f6d6f4c6bf8d63e9/docs/blockchain/raw/bedrock-service-reward-distribution.md)

{.push raises: [], gcsafe.}

import
  std/[algorithm, sequtils, tables],
  ../../core/crypto/hashing,
  ../../core/mantle/[primitives, utxo]

func rewardOpId*(service: ServiceType, epoch: EpochNumber): Hash32 =
  ## ``op_id = hash(ServiceType || epoch_number)``: one discriminant byte for
  ## the service, then 4 little-endian bytes for the epoch (spec §Distribution).
  var preimage: array[5, byte]
  preimage[0] = encodeServiceType(service)
  preimage[1 ..< 5] = encodeLe(epoch)
  blake2b256Hash(preimage)

func cmpByZkId(x, y: (ZkPublicKey, Value)): int =
  cmpNumeric(x[0], y[0])

func distributeRewards*(
    rewards: Table[ZkPublicKey, Value],
    epoch: EpochNumber,
    service: ServiceType,
): seq[Utxo] =
  ## Reward notes sorted by ascending zk_id; the output index is the
  ## position in that sort (spec §Distribution). Zero rewards mint nothing.
  var paid = newSeqOfCap[(ZkPublicKey, Value)](rewards.len)
  for zkId, amount in rewards.pairs:
    if amount > 0:
      paid.add (zkId, amount)
  paid.sort(cmpByZkId)
  let opId = rewardOpId(service, epoch)
  (0 ..< paid.len).mapIt(Utxo(
    opId: opId,
    outputIndex: uint64(it),
    note: Note(value: paid[it][1], zkPublicKey: paid[it][0])))

{.pop.}
