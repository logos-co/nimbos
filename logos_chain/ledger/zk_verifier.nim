# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mockable verifiers. Closure-typed so tests can inject behaviour without
## subclassing. Marked `noSideEffect` because verification is deterministic
## — lets callers stay `func`.

{.push raises: [], gcsafe.}

import poseidon2/types # F

import ../core/mantle/[primitives, proofs]
import ../core/crypto/hashing # ZkHash
import "../core/block/block_types" # ProofOfLeadership

type
  ZkSigVerifier* = proc(pks: seq[ZkPublicKey], msg: ZkHash, sig: ZkSigProof): bool {.
    gcsafe, raises: [], noSideEffect
  .}

  LeaderPublic* = object
    ## Public inputs to leader-proof verification. Built by the cryptarchia
    ## layer from `(epochState.nonce, lottery_*, agedUtxos.root, slot)` plus
    ## the current `latestUtxos.root`.
    slot*: SlotNumber
    epochNonce*: F
    lottery0*: F
    lottery1*: F
    agedRoot*: F
    latestRoot*: F

  LeaderProofVerifier* = proc(proof: ProofOfLeadership, public: LeaderPublic): bool {.
    gcsafe, raises: [], noSideEffect
  .}

func mockAcceptVerifier*(): ZkSigVerifier =
  ## Always returns true. Use in happy-path tests.
  proc(
      pks: seq[ZkPublicKey], msg: ZkHash, sig: ZkSigProof
  ): bool {.gcsafe, raises: [], noSideEffect.} =
    true

func mockRejectVerifier*(): ZkSigVerifier =
  ## Always returns false. Use in negative-path tests.
  proc(
      pks: seq[ZkPublicKey], msg: ZkHash, sig: ZkSigProof
  ): bool {.gcsafe, raises: [], noSideEffect.} =
    false

func mockAcceptLeaderVerifier*(): LeaderProofVerifier =
  ## Always returns true. Use in happy-path tests.
  proc(
      proof: ProofOfLeadership, public: LeaderPublic
  ): bool {.gcsafe, raises: [], noSideEffect.} =
    true

func mockRejectLeaderVerifier*(): LeaderProofVerifier =
  ## Always returns false. Use in negative-path tests.
  proc(
      proof: ProofOfLeadership, public: LeaderPublic
  ): bool {.gcsafe, raises: [], noSideEffect.} =
    false

{.pop.}
