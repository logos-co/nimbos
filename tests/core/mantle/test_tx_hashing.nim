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
  libp2p/crypto/ed25519/ed25519,
  ./test_helpers,
  ../../../logos_chain/core/mantle/[operations, tx_hashing, tx_types, utxo]

proc mkProvider(seed: byte): ProviderId =
  var bytes: array[EdPublicKeySize, byte]
  bytes[0] = seed
  var key: ProviderId
  doAssert key.init(bytes)
  key

suite "core/mantle/tx_hashing":
  test "mantleTxHash is sensitive to tx bytes":
    let txA = MantleTx(
      ops: @[
        createTransferOp(TransferPayload(
          inputs: Inputs(noteIds: @[]),
          outputs: Outputs(notes: @[]),
        )),
      ],
    )
    let txB = MantleTx(ops: @[])
    check mantleTxHash(txA) != mantleTxHash(txB)

  test "mantleTxHash is deterministic":
    let tx = MantleTx(ops: @[])
    check mantleTxHash(tx) == mantleTxHash(tx)

  test "sdp opId is deterministic and payload-sensitive":
    let utxo = mkUtxo(pkSeed = 1)
    let otherUtxo = mkUtxo(pkSeed = 2)
    let declare = DeclarationMessage(
      serviceType: ServiceType.bn,
      locators: @[],
      providerId: mkProvider(1),
      lockedNoteId: id(utxo),
      zkId: utxo.note.zkPublicKey,
    )
    check opId(declare) == opId(declare)
    check opId(declare) != opId(DeclarationMessage(
      serviceType: declare.serviceType,
      locators: declare.locators,
      providerId: declare.providerId,
      lockedNoteId: id(otherUtxo),
      zkId: declare.zkId,
    ))

    var declarationId: DeclarationId
    declarationId[0] = 4'u8
    let withdraw = WithdrawMessage(
      declarationId: declarationId,
      lockedNoteId: id(utxo),
      nonce: 1'u64,
    )
    check opId(withdraw) == opId(withdraw)
    check opId(withdraw) != opId(WithdrawMessage(
      declarationId: declarationId,
      lockedNoteId: id(utxo),
      nonce: 2'u64,
    ))

    let active = ActiveMessage(
      declarationId: declarationId,
      nonce: 1'u64,
      metadata: @[],
    )
    check opId(active) == opId(active)
    check opId(active) != opId(ActiveMessage(
      declarationId: declarationId,
      nonce: 2'u64,
      metadata: @[],
    ))

{.pop.}
