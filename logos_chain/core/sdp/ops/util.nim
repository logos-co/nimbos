# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Shared SDP operation types and helpers.

{.push raises: [], gcsafe.}

import
  results,
  ../state,
  ../../crypto/types,
  ../../../ledger/[types, zksig_verify]

export types, zksig_verify.verifyZkSig

func loadDeclaration*(
    state: SdpState, declarationId: DeclarationId,
): Result[DeclarationInfo, LedgerError] =
  let info = getDeclaration(state, declarationId).valueOr:
    return err(DeclarationNotFound)
  ok(info)

func checkNotWithdrawn*(info: DeclarationInfo): Result[void, LedgerError] =
  if info.withdrawn != 0:
    return err(AlreadyWithdrawn)
  ok()

func checkNonceMonotonic*(
    info: DeclarationInfo, nonce: Nonce,
): Result[void, LedgerError] =
  if nonce <= info.nonce:
    return err(InvalidNonce)
  ok()

{.pop.}
