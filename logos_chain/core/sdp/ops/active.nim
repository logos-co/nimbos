# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP Active validation and application.
## Spec: [1.0.0 Service Declaration Protocol](https://nomos-tech.notion.site/1-0-0-Service-Declaration-Protocol-1fd261aa09df819ca9f8eb2bdfd4ec1d)

{.push raises: [], gcsafe.}

import
  results,
  ./util,
  ../[registry, state],
  ../../mantle/[operations, proofs]

export util, registry, state

func evaluateSdpActivity*(
    service: ServiceType,
    declaration: DeclarationInfo,
    metadata: Metadata,
    blockHeight: BlockNumber,
    params: ServiceParameters,
): bool =
  discard declaration
  discard metadata
  discard blockHeight
  discard params
  case service
  of ServiceType.bn:
    true

proc validateSdpActive(
    active: ActiveMessage,
    proof: ZkSigProof,
    txHash: Hash32,
    state: SdpState,
    genesis: bool = false,
): Result[void, LedgerError] =
  let declaration = ?loadDeclaration(state, active.declarationId)
  ?checkNotWithdrawn(declaration)
  ?checkNonceMonotonic(declaration, active.nonce)

  if not genesis:
    ?verifyZkSig(proof, txHash, @[declaration.zkId])

  ok()

proc tryApplySdpActive*(
    registry: var SdpRegistry,
    active: ActiveMessage,
    proof: ZkSigProof,
    txHash: Hash32,
    blockHeight: BlockNumber,
    genesis: bool = false,
): Result[void, LedgerError] =
  ?validateSdpActive(active, proof, txHash, registry.state, genesis)
  let declaration = registry.state.declarations.getOrDefault(active.declarationId)
  let params = getParametersAt(
    registry, declaration.service, blockHeight,
  ).valueOr:
    return err(MissingServiceParameters)
  if not evaluateSdpActivity(
    declaration.service, declaration, active.metadata, blockHeight, params,
  ):
    return err(ActivityRejected)

  var updated = declaration
  updated.nonce = active.nonce
  updated.active = blockHeight
  registry.state = insertDeclaration(registry.state, active.declarationId, updated)
  indexEvent(
    registry,
    EventType.active,
    declaration.service,
    blockHeight,
    active.declarationId,
  )
  ok()

{.pop.}
