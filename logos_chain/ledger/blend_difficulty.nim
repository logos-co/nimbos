# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Blend proof-of-work difficulty: per-epoch transaction-load tracking and
## the retarget controller.
## Spec: [Mantle §Blend Difficulty](https://github.com/logos-co/logos-lips/blob/22b84507f8ce0bb10f009ffbc5b2305649af6d21/docs/blockchain/raw/bedrock-v1.1-mantle-specification.md#blend-difficulty)
##
## The value is consensus state and a proof-of-quota public input. All
## arithmetic runs on canonical integer representatives, never on field
## elements. Results stay below the field modulus, so the conversion back
## to a field element never reduces.

{.push raises: [], gcsafe.}

import
  results,
  stint,
  ../core/crypto/types,
  ../zk/poseidon2/hasher

export results

type
  EpochLoad* = object
    ## Block and transaction totals of one epoch.
    blocks*: uint64
    txs*: uint64

  TxDensity* = object
    ## Rolling totals of the open epoch and of the last epoch that closed.
    # The controller reads only closed totals. An open epoch still grows,
    # so a value derived from it would depend on the read time.
    currentEpoch*: EpochLoad
    lastClosedEpoch*: Opt[EpochLoad]

const
  # Spec §Blend Difficulty constants. TARGET_TXS_PER_BLOCK is exported
  # for tests that state loads relative to the reference ratio.
  TARGET_TXS_PER_BLOCK* = 512'u64
  BLEND_DAMPING_NUM = 1 ## a, where the exponent is alpha = a / b
  BLEND_DAMPING_DEN = 2 ## b, with 0 < a <= b
  BLEND_MAX_STEP = 2'u64 ## max factor the threshold may move per epoch

  # BN254 scalar-field modulus as an integer. The radicand below reaches
  # ~2^490, so all controller arithmetic runs in 512 bits.
  FieldModulus = StUint[512].fromHex(
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")
  BLEND_DIFFICULTY_BASE = FieldModulus shr 19 ## threshold at reference load

func recordBlock*(d: sink TxDensity, txsInBlock: uint64): TxDensity =
  ## Counts one applied block and its transactions into the open epoch.
  doAssert d.currentEpoch.blocks < high(uint64), "block count overflow"
  doAssert d.currentEpoch.txs <= high(uint64) - txsInBlock,
    "transaction count overflow"
  d.currentEpoch.blocks += 1
  d.currentEpoch.txs += txsInBlock
  d

func closeEpoch*(d: sink TxDensity): TxDensity =
  ## Closes the open epoch's totals and starts counting a new epoch.
  ## Call once per epoch crossed, so a skipped epoch closes as `(0, 0)`.
  d.lastClosedEpoch = Opt.some(d.currentEpoch)
  d.currentEpoch = EpochLoad()
  d

func lastClosedOrEmpty*(d: TxDensity): EpochLoad =
  ## The last closed epoch's totals, or zero load when none closed yet.
  d.lastClosedEpoch.valueOr:
    EpochLoad()

func toU512(value: FieldElement): StUint[512] =
  StUint[512].fromBytesLE(encodeFieldElement(value))

func fromU512(value: StUint[512]): FieldElement =
  # Callers keep the value below the modulus. The low 32 bytes carry it,
  # so the decode cannot fail.
  frFromBytesLE(value.toBytesLE().toOpenArray(0, 31)).expect(
    "value below the field modulus")

let BlendDifficultyBaseFr* =
  # The base threshold as a field element. It is the genesis value and
  # the value for epochs 0 and 1. Reading this `let` makes callers procs.
  fromU512(BLEND_DIFFICULTY_BASE)

func mulChecked(a, b: StUint[512]): Opt[StUint[512]] =
  if a.isZero or b.isZero:
    return Opt.some(stuint(0, 512))
  let r = a * b
  if r div a != b:
    return Opt.none(StUint[512])
  Opt.some(r)

func powChecked(base: StUint[512], n: int): Opt[StUint[512]] =
  var acc = stuint(1, 512)
  for _ in 0 ..< n:
    acc = mulChecked(acc, base).valueOr:
      return Opt.none(StUint[512])
  Opt.some(acc)

func powLeq(base: StUint[512], n: int, x: StUint[512]): bool =
  # Overflow reads as greater. An unrepresentable power exceeds every x.
  let acc = powChecked(base, n).valueOr:
    return false
  acc <= x

func integer_nth_root*(x: StUint[512], n: int): StUint[512] =
  ## The floor of the real n-th root: the largest r with `r^n <= x`.
  ## An approximation that could be off by one would fork the chain.
  # Binary search seeded at 2^256, not at the bit-length seed from the
  # spec pseudocode. For n >= 2 the root of a 512-bit value is below
  # 2^256. Every midpoint power then stays inside 512 bits.
  doAssert n >= 1, "root degree must be positive"
  if n == 1:
    return x
  var
    lo = stuint(0, 512)
    hi = stuint(1, 512) shl 256
  while lo < hi - 1:
    let mid = (lo + hi) shr 1
    if powLeq(mid, n, x):
      lo = mid
    else:
      hi = mid
  lo

func compute_epoch_blend_difficulty*(
    load: EpochLoad, previous: FieldElement
): FieldElement =
  ## Retargets the threshold from one closed epoch's load:
  ## `d = BASE / load^alpha`, clamped to `[previous / k, previous * k]`.
  let
    prev = toU512(previous)
    step = stuint(BLEND_MAX_STEP, 512)
    lo = prev div step
    # `prev` is below 2^254, so the product fits. The modulus cap is
    # necessary: an idle network would double past the modulus, and then
    # every ticket would satisfy the threshold.
    hi = min(prev * step, FieldModulus - 1)
  if load.txs == 0:
    # No load observed. Ease as far as this epoch's clamp allows.
    return fromU512(hi)
  let
    # The load stays an exact ratio `num / den`. Only the final root is
    # floored, so the result is at most one unit from the exact value.
    num = stuint(load.txs, 512)
    den = mulChecked(
        stuint(TARGET_TXS_PER_BLOCK, 512), stuint(load.blocks, 512)).valueOr:
      return fromU512(hi)
    baseTerm = powChecked(BLEND_DIFFICULTY_BASE, BLEND_DAMPING_DEN).valueOr:
      return fromU512(hi)
    denTerm = powChecked(den, BLEND_DAMPING_NUM).valueOr:
      return fromU512(hi)
    # An overflowing radicand means the exact root exceeds the clamp
    # ceiling.
    radicandScaled = mulChecked(baseTerm, denTerm).valueOr:
      return fromU512(hi)
    # An overflowing divisor pushes the exact target below one.
    divisor = powChecked(num, BLEND_DAMPING_NUM).valueOr:
      return fromU512(lo)
    radicand = radicandScaled div divisor
  fromU512(clamp(integer_nth_root(radicand, BLEND_DAMPING_DEN), lo, hi))

{.pop.}
