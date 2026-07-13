# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## SDP declare / withdraw / active validation and application.
## Spec: [1.1.0 Service Declaration Protocol](bedrock-service-declaration-protocol.md)

{.push raises: [], gcsafe.}

import ./ops/[util, declare, withdraw, active]

export util, declare, withdraw, active

{.pop.}
