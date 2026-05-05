# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Genesis-specific aliases/constants layered on top of generic block types.
## Spec: [1.1.0 Bedrock Genesis Block](https://nomos-tech.notion.site/1-1-0-Bedrock-Genesis-Block-330261aa09df809ab143f87766b8d053)

{.push raises: [], gcsafe.}

import ./block_types
import ../crypto/hashing
export block_types, hashing

# ---------------------------------------------------------------------------
# Genesis constants
# ---------------------------------------------------------------------------

const
  GenesisBedrockVersion* = 1'u8

# ---------------------------------------------------------------------------
# Genesis constructors
# ---------------------------------------------------------------------------

func createGenesisHeader(genesisMantleTx: SignedMantleTx): Header =
  ## Genesis header constructor using spec defaults:
  ## - parent block id = zero hash
  ## - slot = 0
  ## - proof-of-leadership fields = zero/default
  initHeader(
    bedrockVersion = GenesisBedrockVersion,
    parentBlock = default(BlockId),
    slot = 0'u64,
    txs = [genesisMantleTx],
    proofOfLeadership = ProofOfLeadership(
      leaderVoucher: default(RewardVoucher),
      entropyContribution: default(ZkHash),
      proof: default(ProofOfLeadershipProof),
      leaderKey: default(Ed25519PublicKey),
    ),
  )

func createGenesisBlock*(genesisMantleTx: SignedMantleTx): Block =
  ## GENESIS_BLOCK = (GENESIS_HEADER, [GENESIS_MANTLE_TX])
  let genesisHeader = createGenesisHeader(genesisMantleTx)
  initBlock(genesisHeader, [genesisMantleTx])

{.pop.}
