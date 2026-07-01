# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  ../../../logos_chain/core/mantle/[primitives, utxo],
  ../../../logos_chain/zk/poseidon2/hasher

func mkZkPubKey*(seed: byte): ZkPublicKey =
  frFromBytesLE([seed]).get

func mkUtxo*(
    value: Value = 100, pkSeed: byte = 1, opIdSeed: byte = 0,
    outputIndex: uint64 = 0,
): Utxo =
  var opId: Hash32
  opId[0] = opIdSeed
  Utxo(
    opId: opId,
    outputIndex: outputIndex,
    note: Note(value: value, zkPublicKey: mkZkPubKey(pkSeed)),
  )

{.pop.}
