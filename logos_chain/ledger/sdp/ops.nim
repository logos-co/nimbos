# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP declare / withdraw / active validation and application.
## Spec: [Service Declaration Protocol v1.8.0](https://github.com/logos-co/logos-lips/blob/bd1ca2c881ae94606d4ab23af1255fd922e85dd6/docs/blockchain/raw/bedrock-service-declaration-protocol.md)

{.push raises: [], gcsafe.}

import ./ops/[util, declare, withdraw, active]

export util, declare, withdraw, active

{.pop.}
