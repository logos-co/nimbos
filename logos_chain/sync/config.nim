# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# ---------------------------------------------------------------------------
# Nim-bincode (``BincodeConfig`` only; payloads use generated ``serialize*ToSeq`` / ``deserialize*``.)
# ---------------------------------------------------------------------------

import bincode
import stew/endians2

# ---------------------------------------------------------------------------
# IBD download request wire limits
# ---------------------------------------------------------------------------

from "../bedrock/block/block_types" import BlockId, ExpectedBedrockVersion, MaxBlockSize

export ExpectedBedrockVersion, MaxBlockSize

const CryptarchiaSyncInnerLengthPrefixSize* = 4
  ## LE ``uint32`` inner-length prefix on every cryptarchia sync ``writeLp`` body.

const
  MaxKnownAdditionalBlocks* = 5
    ## Upper bound on ``KnownBlocks.additionalBlocks`` on the wire (u8 count + 32-byte ids).
    ## Encoders keep a prefix of at most this many extras; decoders reject larger counts.

const MaxIbdDownloadBlocksPerResponse* = 64
  ## Max ``dbrBlock`` messages per ``writeLp`` response frame (anti-spam).

# ---------------------------------------------------------------------------
# Chain-sync bincode config
# ---------------------------------------------------------------------------

const cryptarchiaSyncBincodeConfig* = BincodeConfig(
  byteOrder: LittleEndian,
  intSize: 8,
  sizeLimit: high(uint64),
)

# ---------------------------------------------------------------------------
# Plain u32 length-prefixed bodies inside libp2p ``writeLp`` / ``readLp``
#
# Each message is a libp2p ``writeLp`` / ``readLp`` frame whose body is
# ``uint32`` LE inner length + bincode inner. ``readCryptarchiaPrefixedInner`` reads the
# inner length (4 bytes) then exactly that many inner bytes (see ``initial_block_download``).
# ---------------------------------------------------------------------------

proc addPrefixLengthToPayload*(inner: seq[byte]): seq[byte] {.raises: [BincodeError].} =
  ## Prepends ``inner.len`` as 4 LE bytes, then concatenates ``inner``.
  let n = inner.len.uint64
  if n > uint64(uint32.high):
    raise newException(BincodeError, "cryptarchia sync LP inner length exceeds uint32")
  let le = inner.len.uint32.toBytesLE
  result.setLen(4 + inner.len)
  copyMem(result[0].unsafeAddr, le[0].unsafeAddr, 4)
  if inner.len > 0:
    copyMem(result[4].unsafeAddr, inner[0].unsafeAddr, inner.len)

proc removePrefixLengthFromPacket*(frame: seq[byte]): seq[byte] {.raises: [BincodeError].} =
  ## Inverse of ``addPrefixLengthToPayload``: reads the LE ``uint32`` length prefix from a packet
  ## and returns a copy of the following payload; frame must contain exactly ``4 + len`` bytes.
  if frame.len < 4:
    raise newException(BincodeError, "cryptarchia sync LP frame too short for length prefix")
  let ln = uint32.fromBytesLE(frame.toOpenArray(0, 3)).uint64
  let expected = ln + 4'u64
  if expected != frame.len.uint64:
    raise newException(BincodeError, "cryptarchia sync LP frame length mismatch")
  if ln > uint64(int.high):
    raise newException(BincodeError, "cryptarchia sync LP payload too large")
  let plen = int ln
  if plen > 0:
    result.setLen(plen)
    copyMem(result[0].unsafeAddr, frame[4].unsafeAddr, plen)
  else:
    result = @[]

{.pop.}
