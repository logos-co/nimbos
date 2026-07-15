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

suite "ledger/sdp/ops/active":
  test "tryApplySdpActive rejects unknown declaration and bad nonce":
    var seeded = seedDeclaration(pkSeed = 21, declareEpoch = 10)
    var unknown = ActiveMessage(
      declarationId: seeded.declId,
      nonce: 1,
      metadata: @[],
    )
    unknown.declarationId[0] = byte(77)
    check execActive(seeded, unknown, 15).isErr

    let stale = ActiveMessage(
      declarationId: seeded.declId,
      nonce: 0,
      metadata: @[],
    )
    check execActive(seeded, stale, 15).isErr

  test "tryApplySdpActive accepts declaration with withdraw intent":
    var seeded = seedDeclaration(pkSeed = 22, declareEpoch = 10)
    let withdraw = WithdrawMessage(
      declarationId: seeded.declId,
      lockedNoteId: seeded.declaration.lockedNoteId,
      nonce: 1,
    )
    installTestWithdraw(seeded.registry, withdraw, 15)
    let active = ActiveMessage(
      declarationId: seeded.declId,
      nonce: 2,
      metadata: @[],
    )
    installTestActive(seeded.registry, active, 15)
    let info = getDeclaration(seeded.registry.state, seeded.declId).get()
    check info.active == Opt.some(15'u64)

  test "tryApplySdpActive updates active field":
    var seeded = seedDeclaration(pkSeed = 23, declareEpoch = 10)
    let active = ActiveMessage(
      declarationId: seeded.declId,
      nonce: 1,
      metadata: @[],
    )
    installTestActive(seeded.registry, active, 25)
    let info = getDeclaration(seeded.registry.state, seeded.declId).get()
    check info.active == Opt.some(25'u64)
    check info.nonce == 1'u64

{.pop.}
