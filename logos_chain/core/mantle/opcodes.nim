# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Mantle operation opcode constants.
## Spec: [v1.5.0 Mantle](https://nomos-tech.notion.site/1-5-0-Mantle-33d261aa09df8051b0d0cd4d5ddade85)
## Wire encoding/decoding: [v1.4.1 Mantle Transaction Encoding](https://nomos-tech.notion.site/1-4-1-Mantle-Transaction-Encoding-33e261aa09df8050beb6c9b72a042217)

{.push raises: [], gcsafe.}

const
  OpTransfer* = 0x00'u8
  OpChannelConfig* = 0x10'u8
  OpChannelInscribe* = 0x11'u8
  OpChannelDeposit* = 0x12'u8
  OpChannelWithdraw* = 0x13'u8
  OpChannelTransfer* = 0x14'u8
  OpSdpDeclare* = 0x20'u8
  OpSdpWithdraw* = 0x21'u8
  OpSdpActive* = 0x22'u8
  OpLeaderClaim* = 0x30'u8

{.pop.}
