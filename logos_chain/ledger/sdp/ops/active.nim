# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP Active validation and application.
## Spec: [Service Declaration Protocol v1.3.0](https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/raw/bedrock-service-declaration-protocol.md)

{.push raises: [], gcsafe.}

import
  results,
  ./util,
  ../[registry, state],
  ../../../core/mantle/[operations, proofs]

export util, registry, state

func evaluateSdpActivity(
    service: ServiceType,
    declaration: DeclarationInfo,
    metadata: Metadata,
    epoch: EpochNumber,
    params: ServiceParameters,
): bool =
  ## Service-specific activity check. Blend Network proof validation is not
  ## implemented yet; BN currently accepts any metadata.
  discard declaration
  discard metadata
  discard epoch
  discard params
  case service
  of ServiceType.bn:
    true

proc validateSdpActive(
    active: ActiveMessage,
    proof: ZkSigProof,
    txHash: Hash32,
    state: SdpState,
): Result[DeclarationInfo, LedgerError] =
  let declaration = ?loadDeclaration(state, active.declarationId)
  ?checkNonceMonotonic(declaration, active.nonce)
  ?verifyZkSig(proof, txHash, @[declaration.zkId])
  ok(declaration)

proc applySdpActive*(
    registry: sink SdpRegistry,
    active: ActiveMessage,
    declaration: DeclarationInfo,
    epoch: EpochNumber,
): SdpRegistry =
  ## Mutation only; assumes validation passed.
  var updated = declaration
  updated.nonce = active.nonce
  updated.active = Opt.some(epoch)
  registry.state = insertDeclaration(registry.state, active.declarationId, updated)
  registry

proc tryApplySdpActive*(
    registry: sink SdpRegistry,
    active: ActiveMessage,
    proof: ZkSigProof,
    txHash: Hash32,
    epoch: EpochNumber,
): Result[SdpRegistry, LedgerError] =
  let declaration = ?validateSdpActive(active, proof, txHash, registry.state)
  let params = getParametersAt(
    registry, declaration.service, epoch,
  ).valueOr:
    return err(MissingServiceParameters)
  if not evaluateSdpActivity(
    declaration.service, declaration, active.metadata, epoch, params,
  ):
    return err(ActivityRejected)
  ok(applySdpActive(registry, active, declaration, epoch))

{.pop.}
