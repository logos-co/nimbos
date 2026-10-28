# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  ../../../testsuite,
  results,
  ../test_helpers

suite "ledger/sdp/ops/withdraw":
  test "tryApplySdpWithdraw rejects unknown declaration":
    let seeded = seedDeclaration(pkSeed = 11, declareEpoch = 10)
    var unknown = WithdrawMessage(
      declarationId: seeded.declId,
      lockedNoteId: seeded.declaration.lockedNoteId,
      nonce: 1,
    )
    unknown.declarationId[0] = byte(99)
    check execWithdraw(seeded, unknown, 15).error == DeclarationNotFound

  test "tryApplySdpWithdraw rejects a second withdraw":
    var seeded = seedDeclaration(pkSeed = 12, declareEpoch = 10)
    let withdraw = WithdrawMessage(
      declarationId: seeded.declId,
      lockedNoteId: seeded.declaration.lockedNoteId,
      nonce: 1,
    )
    installTestWithdraw(seeded.registry, withdraw, withdrawAt = 15)
    var second = withdraw
    second.nonce = 2
    check execWithdraw(seeded, second, 15).error == AlreadyWithdrawn

  test "tryApplySdpWithdraw rejects a stale nonce":
    let
      seeded = seedDeclaration(pkSeed = 14, declareEpoch = 10)
      stale = WithdrawMessage(
        declarationId: seeded.declId,
        lockedNoteId: seeded.declaration.lockedNoteId,
        nonce: 0,
      )
    check execWithdraw(seeded, stale, 16).error == InvalidNonce

  test "tryApplySdpWithdraw rejects a mismatched locked note":
    let
      seeded = seedDeclaration(pkSeed = 16, declareEpoch = 1)
      mismatched = WithdrawMessage(
        declarationId: seeded.declId,
        lockedNoteId: default(NoteId),
        nonce: 1,
      )
    check execWithdraw(seeded, mismatched, 2).error == LockedNoteIdMismatch

  test "applySdpWithdraw schedules the withdrawal two epochs ahead":
    var seeded = seedDeclaration(pkSeed = 13, declareEpoch = 1)
    let
      withdraw = WithdrawMessage(
        declarationId: seeded.declId,
        lockedNoteId: seeded.declaration.lockedNoteId,
        nonce: 1,
      )
      declaration = getDeclaration(seeded.registry.state, seeded.declId).get()
    seeded.registry = applySdpWithdraw(seeded.registry, withdraw, declaration, 3)
    let info = getDeclaration(seeded.registry.state, seeded.declId).get()
    check info.withdrawAt == Opt.some(5'u32)
    check info.nonce == 1'u64
    check getLockedNote(seeded.registry.state, seeded.declaration.lockedNoteId).isSome

  test "tryApplySdpWithdraw rejects an epoch too close to the limit":
    let
      seeded = seedDeclaration(pkSeed = 15, declareEpoch = 1)
      withdraw = WithdrawMessage(
        declarationId: seeded.declId,
        lockedNoteId: seeded.declaration.lockedNoteId,
        nonce: 1,
      )
    check execWithdraw(seeded, withdraw, high(EpochNumber) - 1).error ==
      InvalidEpoch
    # One epoch lower passes the gate and reaches the signature step.
    check execWithdraw(seeded, withdraw, high(EpochNumber) - 2).error in
      {VerifierNotInitialised, PermanentInvalidTxProof}

{.pop.}
