# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.


{.push raises: [], gcsafe.}

import
  ../core/mantle/[primitives, proofs],
  ../core/crypto/hashing

type
  ZkSigVerifier* = proc(pks: seq[ZkPublicKey], msg: ZkHash, sig: ZkSigProof): bool {.
    gcsafe, raises: [], noSideEffect
  .}

func mockAcceptVerifier*(): ZkSigVerifier =
  ## Always returns true. Use in happy-path tests.
  proc(
      pks: seq[ZkPublicKey], msg: ZkHash, sig: ZkSigProof
  ): bool =
    true

func mockRejectVerifier*(): ZkSigVerifier =
  ## Always returns false. Use in negative-path tests.
  proc(
      pks: seq[ZkPublicKey], msg: ZkHash, sig: ZkSigProof
  ): bool =
    false

{.pop.}
