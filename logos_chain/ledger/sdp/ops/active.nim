# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP Active validation and application.
## Spec: [Service Declaration Protocol v1.8.0](https://github.com/logos-co/logos-lips/blob/bd1ca2c881ae94606d4ab23af1255fd922e85dd6/docs/blockchain/raw/bedrock-service-declaration-protocol.md)

{.push raises: [], gcsafe.}

import
  ./util,
  ../[registry, state],
  ../../../core/mantle/[operations, proofs]

export util, registry, state

proc validateSdpActive(
    active: ActiveMessage,
    proof: ZkSigProof,
    txHash: Hash32,
    state: SdpState,
    epoch: EpochNumber,
): Result[DeclarationInfo, LedgerError] =
  let declaration = ?loadDeclaration(state, active.declarationId)
  ?checkWithinWithdrawal(declaration, epoch)
  ?checkNonce(declaration, active.nonce)
  ?verifyZkSig(proof, txHash, [declaration.zkId])
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
    verifyPoq: ProofOfQuotaVerifier,
): Result[SdpRegistry, LedgerError] =
  let declaration = ?validateSdpActive(
    active, proof, txHash, registry.state, epoch)
  if getParametersAt(registry, declaration.service, epoch).isNone:
    return err(MissingServiceParameters)
  case declaration.service
  of ServiceType.bn:
    registry.blendRewards = ?recordActivity(
      registry.blendRewards, active.metadata, declaration.providerId, verifyPoq)
  ok(applySdpActive(registry, active, declaration, epoch))

{.pop.}
