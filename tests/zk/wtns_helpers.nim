# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Test-only decoder for the snarkjs `.wtns` v2 container the witness
## generators emit. Production hands the bytes to rapidsnark unparsed.
##
## Layout, little-endian, no padding:
##   "wtns" u32 version=2 u32 nSections=2
##   [id=1, len=40: u32 n8=32, r (32 bytes), u32 nVars]
##   [id=2, len=32*nVars: nVars field elements]

{.push raises: [].}

import
  stew/endians2,
  results,
  ../../logos_chain/zk/poseidon2/hasher

export results, hasher

type
  WtnsDecodeError* {.pure.} = enum
    TooShort
    BadMagic
    BadVersion
    BadSectionCount
    BadHeaderSection
    BadFieldSize
    BadDataSection
    LengthMismatch
    ValueOutOfRange

const
  WtnsHeaderLen = 76
  FrLen = 32

func u32At(bytes: openArray[byte], pos: int): uint32 =
  uint32.fromBytesLE(bytes.toOpenArray(pos, pos + 3))

func u64At(bytes: openArray[byte], pos: int): uint64 =
  uint64.fromBytesLE(bytes.toOpenArray(pos, pos + 7))

func decodeWtns*(bytes: openArray[byte]): Result[seq[FieldElement], WtnsDecodeError] =
  if bytes.len < WtnsHeaderLen:
    return err(TooShort)
  if bytes[0] != byte('w') or bytes[1] != byte('t') or
      bytes[2] != byte('n') or bytes[3] != byte('s'):
    return err(BadMagic)
  if u32At(bytes, 4) != 2:
    return err(BadVersion)
  if u32At(bytes, 8) != 2:
    return err(BadSectionCount)
  if u32At(bytes, 12) != 1 or u64At(bytes, 16) != 40:
    return err(BadHeaderSection)
  if u32At(bytes, 24) != uint32(FrLen):
    return err(BadFieldSize)
  let nVars = int(u32At(bytes, 60))
  if u32At(bytes, 64) != 2 or u64At(bytes, 68) != uint64(FrLen * nVars):
    return err(BadDataSection)
  if bytes.len != WtnsHeaderLen + FrLen * nVars:
    return err(LengthMismatch)
  var values = newSeqOfCap[FieldElement](nVars)
  for i in 0 ..< nVars:
    let
      start = WtnsHeaderLen + i * FrLen
      value = frFromBytesLE(bytes.toOpenArray(start, start + FrLen - 1)).valueOr:
        return err(ValueOutOfRange)
    values.add(value)
  ok(values)

{.pop.}
