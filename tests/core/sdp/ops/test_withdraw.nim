# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  results,
  ../test_helpers

suite "core/sdp/ops/withdraw":
  test "tryApplySdpWithdraw rejects unknown declaration":
    var seeded = seedDeclaration(pkSeed = 11, declareEpoch = 10)
    var unknown = WithdrawMessage(
      declarationId: seeded.declId,
      lockedNoteId: seeded.declaration.lockedNoteId,
      nonce: 1,
    )
    unknown.declarationId[0] = byte(99)
    check execWithdraw(seeded, unknown, 15).isErr

  test "tryApplySdpWithdraw rejects bad nonce and already withdrawn":
    var seeded = seedDeclaration(pkSeed = 12, declareEpoch = 10)
    let withdraw = WithdrawMessage(
      declarationId: seeded.declId,
      lockedNoteId: seeded.declaration.lockedNoteId,
      nonce: 1,
    )
    installTestWithdraw(seeded.registry, withdraw, 15)

    check execWithdraw(seeded, withdraw, 16).isErr

    var replay = withdraw
    replay.nonce = 0
    check execWithdraw(seeded, replay, 16).isErr

  test "tryApplySdpWithdraw sets withdraw_at and keeps note locked until finalization":
    var seeded = seedDeclaration(pkSeed = 13, declareEpoch = 10)
    let withdraw = WithdrawMessage(
      declarationId: seeded.declId,
      lockedNoteId: seeded.declaration.lockedNoteId,
      nonce: 1,
    )
    installTestWithdraw(seeded.registry, withdraw, 5)
    let info = getDeclaration(seeded.registry.state, seeded.declId).get()
    check info.withdrawAt == Opt.some(5'u64)
    check info.nonce == 1'u64
    check getLockedNote(seeded.registry.state, seeded.declaration.lockedNoteId).isSome

    seeded.registry.state = finalizeWithdrawals(seeded.registry.state, 6)
    check getDeclaration(seeded.registry.state, seeded.declId).isSome
    seeded.registry.state = finalizeWithdrawals(seeded.registry.state, 7)
    check getDeclaration(seeded.registry.state, seeded.declId).isNone
    check getLockedNote(seeded.registry.state, seeded.declaration.lockedNoteId).isNone

{.pop.}
