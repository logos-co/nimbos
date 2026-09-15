# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Test-side alias of the production snarkjs JSON codec. Tests feed
## committed `proof.json` / `public.json` fixtures through it.

{.push raises: [].}

import
  ../../logos_chain/zk/groth16/snarkjs

export snarkjs

{.pop.}
