# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle **transaction** layer: re-exports **``mantle/primitives``** and
## **``mantle/operations``**; **``Op``** (``Opcode`` + **``OpPayload``**),
## **``MantleTx``** / **``SignedMantleTx``**, and **``OpProof``**.
## Spec: [v1.4 Mantle](https://nomos-tech.notion.site/v1-4-Mantle-335261aa09df8065a38acff4b25aee82)

{.push raises: [], gcsafe.}

import ./[primitives, operations, proofs]
export primitives, operations, proofs

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

type
  MantleTx* = object
    ops*: seq[Op]
    permanentStorageGasPrice*: TokenValue
    executionGasPrice*: TokenValue

  ## ``MantleTx`` plus one **``OpProof``** per op: ``opProofs[i]`` lines up with ``tx.ops[i]``.
  SignedMantleTx* = object
    tx*: MantleTx
    opProofs*: seq[OpProof]

{.pop.}
