# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## The test-only `.wtns` v2 decoder that the witness-generation tests read
## public signals through.

{.push raises: [].}
{.used.}

import
  std/algorithm,
  unittest2,
  stew/endians2,
  ./wtns_helpers

suite "zk/wtns_helpers — wtns decoder":
  func header(nVars: uint32): seq[byte] =
    var bytes = @[byte 'w', byte 't', byte 'n', byte 's', 2, 0, 0, 0, 2, 0, 0, 0,
      1, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0]
    bytes.setLen(60)
    bytes.add(nVars.toBytesLE)
    bytes.add([byte 2, 0, 0, 0])
    bytes.add(uint64(32 * nVars).toBytesLE)
    bytes

  test "rejects a short buffer":
    check decodeWtns([byte 1, 2, 3]).error == WtnsDecodeError.TooShort

  test "rejects a bad magic":
    var bytes = header(1)
    bytes.setLen(76 + 32)
    bytes[0] = byte 'x'
    check decodeWtns(bytes).error == WtnsDecodeError.BadMagic

  test "rejects a length mismatch":
    var bytes = header(2)
    bytes.setLen(76 + 32)
    check decodeWtns(bytes).error == WtnsDecodeError.LengthMismatch

  test "rejects a value at or above the field order":
    var bytes = header(1)
    bytes.setLen(76 + 32)
    bytes.toOpenArray(76, 107).fill(0xff)
    check decodeWtns(bytes).error == WtnsDecodeError.ValueOutOfRange

  test "decodes a single zero value":
    var bytes = header(1)
    bytes.setLen(76 + 32)
    let values = decodeWtns(bytes).expect("decodes")
    check values.len == 1
    check values[0] == zero

{.pop.}
