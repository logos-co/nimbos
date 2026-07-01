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
  ../../logos_chain/ledger/channel_state,
  ../../logos_chain/core/mantle/primitives

proc mkChan(
    tipSlot: uint64,
    tipSequencer: uint16,
    tipSequencerStartingSlot: uint64,
    postingTimeframe: uint32,
    postingTimeout: uint32,
    numKeys: int,
): ChannelState =
  ChannelState(
    tipSlot: SlotNumber(tipSlot),
    tipSequencer: ChannelKeyIndex(tipSequencer),
    tipSequencerStartingSlot: SlotNumber(tipSequencerStartingSlot),
    postingTimeframe: PostingTimeframe(postingTimeframe),
    postingTimeout: PostingTimeout(postingTimeout),
    balance: 0,
    withdrawalNonce: 0,
    accreditedKeys: newSeq[Ed25519PublicKey](numKeys),
    configurationThreshold: 0,
    tipMessage: default(Hash32),
    withdrawThreshold: 0,
  )

suite "round_robin — infinite timeframe (postingTimeframe=0)":
  test "no timeout, sequencer holds forever":
    let chan = mkChan(100, 2, 80, 0, 0, 5)
    check round_robin(SlotNumber(100), chan) == (ChannelKeyIndex(2), SlotNumber(80))
    check round_robin(SlotNumber(999_999), chan) == (ChannelKeyIndex(2), SlotNumber(80))

  test "not yet timed out, sequencer holds":
    let chan = mkChan(100, 1, 90, 0, 50, 4)
    check round_robin(SlotNumber(130), chan) == (ChannelKeyIndex(1), SlotNumber(90))

  test "timed out once, single rotation":
    let chan = mkChan(100, 1, 90, 0, 50, 4)
    check round_robin(SlotNumber(150), chan) == (ChannelKeyIndex(2), SlotNumber(150))

  test "timed out multiple times, cascaded rotation":
    let chan = mkChan(100, 1, 90, 0, 50, 4)
    check round_robin(SlotNumber(220), chan) == (ChannelKeyIndex(3), SlotNumber(200))

suite "round_robin — timeframe rotation (no timeout)":
  test "same slot, no advance":
    let chan = mkChan(100, 0, 100, 10, 0, 3)
    check round_robin(SlotNumber(100), chan) == (ChannelKeyIndex(0), SlotNumber(100))

  test "within first frame, no rotation":
    let chan = mkChan(100, 0, 100, 10, 0, 3)
    check round_robin(SlotNumber(105), chan) == (ChannelKeyIndex(0), SlotNumber(100))

  test "exact boundary, rotates once":
    let chan = mkChan(100, 0, 100, 10, 0, 3)
    check round_robin(SlotNumber(110), chan) == (ChannelKeyIndex(1), SlotNumber(110))

  test "multiple frames, rotates n times":
    let chan = mkChan(100, 0, 100, 10, 0, 4)
    check round_robin(SlotNumber(125), chan) == (ChannelKeyIndex(2), SlotNumber(120))

  test "rotation wraps around key list":
    let chan = mkChan(100, 2, 100, 10, 0, 3)
    check round_robin(SlotNumber(110), chan) == (ChannelKeyIndex(0), SlotNumber(110))

  test "full cycle returns to same sequencer":
    let chan = mkChan(100, 1, 100, 10, 0, 3)
    check round_robin(SlotNumber(130), chan) == (ChannelKeyIndex(1), SlotNumber(130))

  test "starting slot offset from tip slot":
    let chan = mkChan(100, 0, 95, 10, 0, 3)
    check round_robin(SlotNumber(105), chan) == (ChannelKeyIndex(1), SlotNumber(105))

suite "round_robin — timeout rotation":
  test "exact boundary, one timeout":
    let chan = mkChan(100, 0, 100, 10, 20, 4)
    check round_robin(SlotNumber(120), chan) == (ChannelKeyIndex(1), SlotNumber(120))

  test "skips multiple unresponsive sequencers":
    let chan = mkChan(100, 0, 100, 5, 10, 4)
    check round_robin(SlotNumber(135), chan) == (ChannelKeyIndex(3), SlotNumber(130))

  test "wraps past end of key list":
    let chan = mkChan(100, 2, 100, 5, 10, 3)
    check round_robin(SlotNumber(120), chan) == (ChannelKeyIndex(1), SlotNumber(120))

  test "wraps full cycle":
    let chan = mkChan(100, 0, 100, 5, 10, 3)
    check round_robin(SlotNumber(130), chan) == (ChannelKeyIndex(0), SlotNumber(130))

suite "round_robin — priority selection":
  test "no timeout, rotates by timeframe even after long absence":
    let chan = mkChan(100, 0, 100, 10, 0, 3)
    check round_robin(SlotNumber(1100), chan) == (ChannelKeyIndex(1), SlotNumber(1100))

  test "just below timeout threshold uses timeframe branch":
    let chan = mkChan(100, 0, 100, 10, 20, 4)
    check round_robin(SlotNumber(119), chan) == (ChannelKeyIndex(1), SlotNumber(110))

suite "round_robin — sequencer count edge cases":
  test "single key always returns index 0":
    let chan = mkChan(100, 0, 100, 10, 20, 1)
    check round_robin(SlotNumber(100), chan).index == ChannelKeyIndex(0)
    check round_robin(SlotNumber(115), chan).index == ChannelKeyIndex(0)
    check round_robin(SlotNumber(130), chan).index == ChannelKeyIndex(0)

  test "two sequencers alternate":
    let chan = mkChan(100, 0, 100, 5, 0, 2)
    check round_robin(SlotNumber(100), chan).index == ChannelKeyIndex(0)
    check round_robin(SlotNumber(104), chan).index == ChannelKeyIndex(0)
    check round_robin(SlotNumber(105), chan).index == ChannelKeyIndex(1)
    check round_robin(SlotNumber(109), chan).index == ChannelKeyIndex(1)
    check round_robin(SlotNumber(110), chan).index == ChannelKeyIndex(0)

  test "fifty sequencers rotate and wrap":
    let chan = mkChan(0, 0, 0, 5, 0, 50)
    # After 5 slots -> sequencer 1
    check round_robin(SlotNumber(5), chan).index == ChannelKeyIndex(1)
    # After 5*49 = 245 slots -> sequencer 49 (last)
    check round_robin(SlotNumber(245), chan).index == ChannelKeyIndex(49)
    # After 5*50 = 250 slots -> wrap back to 0
    check round_robin(SlotNumber(250), chan).index == ChannelKeyIndex(0)
    # After 5*73 = 365 slots -> (0+73)%50 = 23
    check round_robin(SlotNumber(365), chan).index == ChannelKeyIndex(23)

  test "fifty sequencers cascading timeouts":
    let chan = mkChan(1000, 10, 1000, 5, 3, 50)
    check round_robin(SlotNumber(1090), chan) ==
      (ChannelKeyIndex(40), SlotNumber(1090))

suite "round_robin — state transitions":
  test "after timeout, new sequencer gets fresh starting slot":
    let chan = mkChan(110, 1, 110, 15, 10, 3)
    check round_robin(SlotNumber(125), chan) == (ChannelKeyIndex(2), SlotNumber(120))
    check round_robin(SlotNumber(135), chan) == (ChannelKeyIndex(0), SlotNumber(130))

  test "zero elapsed (block_slot == tip_slot), no change":
    let chan = mkChan(100, 3, 95, 10, 20, 5)
    check round_robin(SlotNumber(100), chan) == (ChannelKeyIndex(3), SlotNumber(95))

{.pop.}
