# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/json,
  chronicles,
  stew/[base10, byteutils],
  libp2p/peerid,
  presto/common as presto_common,
  ssz_serialization,
  ./lb_rest_json_serialization

export peerid, presto_common, lb_rest_json_serialization, ssz_serialization

func decodeMediaType*(
    contentType: Opt[ContentTypeData]): Result[MediaType, string] =
  if contentType.isNone or isWildCard(contentType.get.mediaType):
    return err("Missing or incorrect Content-Type")
  ok contentType.get.mediaType

const
  DecimalSet = {'0' .. '9'}
    # Base10 (decimal) set of chars

  ApplicationJsonMediaType* = MediaType.init("application/json")
  TextPlainMediaType* = MediaType.init("text/plain")
  OctetStreamMediaType* = MediaType.init("application/octet-stream")
  UrlEncodedMediaType* = MediaType.init("application/x-www-form-urlencoded")
  UnableDecodeVersionError = "Unable to decode version"
  UnableDecodeError = "Unable to decode data"
  InvalidContentTypeError* = "Invalid content type"
  UnexpectedForkVersionError* = "Unexpected fork version received"

type
  EncodeTypes* =
    EmptyBody |
    RestNimbusTimestamp1

  DecodeTypes* =
    DataEnclosedObject |
    DataMetaEnclosedObject |
    DataRootEnclosedObject |
    DataOptimisticObject |
    DataVersionEnclosedObject |
    DataOptimisticAndFinalizedObject |
    RestErrorMessage |
    RestNimbusTimestamp1 |
    RestNimbusTimestamp2

  RestVersioned*[T] = object
    data*: T

func ethHeaders(
    hasRestAllowedOrigin: bool): HttpTable = HttpTable.init([])

func ethHeaders(
    isBlinded: bool,
    executionValue: UInt256,
    consensusValue: UInt256,
    hasRestAllowedOrigin: bool): HttpTable =
  HttpTable.init([])

func readStrictHexChar(c: char, radix: static[uint8]): Result[int8, cstring] =
  ## Converts an hex char to an int
  const
    lowerLastChar = chr(ord('a') + radix - 11'u8)
    capitalLastChar = chr(ord('A') + radix - 11'u8)
  case c
  of '0' .. '9': ok(int8 ord(c) - ord('0'))
  of 'a' .. lowerLastChar: ok(int8 ord(c) - ord('a') + 10)
  of 'A' .. capitalLastChar: ok(int8 ord(c) - ord('A') + 10)
  else: err("Invalid hexadecimal character encountered!")

func readStrictDecChar(c: char, radix: static[uint8]): Result[int8, cstring] =
  const lastChar = char(ord('0') + radix - 1'u8)
  case c
  of '0' .. lastChar: ok(int8 ord(c) - ord('0'))
  else: err("Invalid decimal character encountered!")

func skipPrefixes(str: string,
                  radix: range[2..16]): Result[int, cstring] =
  ## Returns the index of the first meaningful char in `hexStr` by skipping
  ## "0x" prefix
  if len(str) < 2:
    return ok(0)

  return
    if str[0] == '0':
      if str[1] in {'x', 'X'}:
        if radix != 16:
          return err("Parsing mismatch, 0x prefix is only valid for a " &
                     "hexadecimal number (base 16)")
        ok(2)
      elif str[1] in {'o', 'O'}:
        if radix != 8:
          return err("Parsing mismatch, 0o prefix is only valid for an " &
                     "octal number (base 8)")
        ok(2)
      elif str[1] in {'b', 'B'}:
        if radix == 2:
          ok(2)
        elif radix == 16:
          # allow something like "0bcdef12345" which is a valid hex
          ok(0)
        else:
          err("Parsing mismatch, 0b prefix is only valid for a binary number " &
              "(base 2), or hex number")
      else:
        ok(0)
    else:
      ok(0)

func strictParse*[bits: static[int]](input: string,
                                     T: typedesc[StUint[bits]],
                                     radix: static[uint8] = 10
                                    ): Result[T, cstring] {.raises: [].} =
  var res: T
  static: doAssert (radix >= 2) and (radix <= 16),
            "Only base from 2..16 are supported"

  const
    base = radix.uint8.stuint(bits)
    zero = 0.uint8.stuint(256)

  var currentIndex =
    block:
      let res = skipPrefixes(input, radix)
      if res.isErr():
        return err(res.error)
      res.get()

  while currentIndex < len(input):
    let value =
      when radix <= 10:
        ? readStrictDecChar(input[currentIndex], radix)
      else:
        ? readStrictHexChar(input[currentIndex], radix)
    let mres = res * base
    if (res != zero) and (mres div base != res):
      return err("Overflow error")
    let ares = mres + value.stuint(bits)
    if ares < mres:
      return err("Overflow error")
    res = ares
    inc(currentIndex)
  ok(res)

template withRestJsonWriter(w, typ, body: untyped): untyped =
  try:
    var stream = memoryOutput()
    var w = JsonWriter[RestJson].init(stream)
    body
    stream.getOutput(typ)
  except IOError:
    raiseAssert "No IOError from memoryOutput"

proc prepareJsonResponse*(_: typedesc[RestApiResponse], d: auto): seq[byte] =
  withRestJsonWriter(w, seq[byte]):
    w.writeObject:
      w.writeField("data", d)

proc prepareJsonStringResponse*(_: typedesc[RestApiResponse], d: auto): string =
  RestJson.encode(d)

proc jsonResponse*(_: typedesc[RestApiResponse], data: auto): RestApiResponse =
  let res = withRestJsonWriter(w, seq[byte]):
    w.writeObject:
      w.writeField("data", data)

  RestApiResponse.response(res, Http200, "application/json")

proc jsonResponseWOpt*(_: typedesc[RestApiResponse], data: auto,
                       execOpt: Opt[bool]): RestApiResponse =
  let res = withRestJsonWriter(w, seq[byte]):
    w.writeObject:
      w.writeField("execution_optimistic", execOpt)
      w.writeField("data", data)

  RestApiResponse.response(res, Http200, "application/json")

proc prepareJsonResponseFinalized*(
    _: typedesc[RestApiResponse], data: auto, exec: Opt[bool],
    finalized: bool
): seq[byte] =
  withRestJsonWriter(w, seq[byte]):
    w.writeObject:
      w.writeField("execution_optimistic", exec)
      w.writeField("finalized", finalized)
      w.writeField("data", data)

proc jsonResponseFinalized*(_: typedesc[RestApiResponse], data: auto,
                            exec: Opt[bool],
                            finalized: bool): RestApiResponse =
  let res = RestApiResponse.prepareJsonResponseFinalized(data, exec, finalized)
  RestApiResponse.response(res, Http200, "application/json")

proc jsonResponseFinalizedWVersion*(
    _: typedesc[RestApiResponse],
    data: auto,
    exec: Opt[bool],
    finalized: bool,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    headers = ethHeaders(hasRestAllowedOrigin)
    res = withRestJsonWriter(w, seq[byte]):
      w.writeObject:
        w.writeField("execution_optimistic", exec)
        w.writeField("finalized", finalized)
        w.writeField("data", data)

  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponseWVersion*(
    _: typedesc[RestApiResponse],
    data: auto,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    headers = ethHeaders(hasRestAllowedOrigin)
    res = withRestJsonWriter(w, seq[byte]):
      w.writeObject:
        w.writeField("version", version)
        w.writeField("data", data)

  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonPlainEncoded(data: auto): seq[byte] =
  withRestJsonWriter(w, seq[byte]):
    w.writeValue(data)

proc jsonResponsePlain*(_: typedesc[RestApiResponse],
                        data: auto): RestApiResponse =
  let res = data.jsonPlainEncoded()
  RestApiResponse.response(res, Http200, "application/json")

proc jsonResponsePlain*(
    _: typedesc[RestApiResponse],
    data: auto,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    res = data.jsonPlainEncoded()
    headers = ethHeaders(hasRestAllowedOrigin)
  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponsePlain*(
    _: typedesc[RestApiResponse],
    data: auto,
    isBlinded: bool,
    executionValue: UInt256,
    consensusValue: UInt256,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    res = data.jsonPlainEncoded()
    headers = ethHeaders(
      isBlinded, executionValue, consensusValue, hasRestAllowedOrigin)
  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponseWMeta*(_: typedesc[RestApiResponse],
                        data: auto, meta: auto): RestApiResponse =
  let res = withRestJsonWriter(w, seq[byte]):
    w.writeObject:
      w.writeField("data", data)
      w.writeField("meta", meta)

  RestApiResponse.response(res, Http200, "application/json")

proc jsonMsgResponse*(_: typedesc[RestApiResponse],
                      msg: string = ""): RestApiResponse =
  let data = withRestJsonWriter(w, seq[byte]):
    w.writeObject:
      w.writeField("code", 200)
      w.writeField("message", msg)

  RestApiResponse.response(data, Http200, "application/json")

proc jsonError*(_: typedesc[RestApiResponse], status: HttpCode = Http200,
                msg: string = ""): RestApiResponse =
  let data = withRestJsonWriter(w, string):
    w.writeObject:
      w.writeField("code", int(status.toInt()))
      w.writeField("message", msg)

  RestApiResponse.error(status, data, "application/json")

proc jsonError*(_: typedesc[RestApiResponse], status: HttpCode = Http200,
                msg: string = "", stacktrace: string): RestApiResponse =
  let data = withRestJsonWriter(w, string):
    w.writeObject:
      w.writeField("code", int(status.toInt()))
      w.writeField("message", msg)
      if len(stacktrace) > 0:
        w.writeField("stacktraces", [stacktrace])

  RestApiResponse.error(status, data, "application/json")

proc jsonError*(_: typedesc[RestApiResponse], status: HttpCode = Http200,
                msg: string = "",
                stacktraces: openArray[string]): RestApiResponse =
  let data = withRestJsonWriter(w, string):
    w.writeObject:
      w.writeField("code", int(status.toInt()))
      w.writeField("message", msg)
      w.writeField("stacktraces", stacktraces)

  RestApiResponse.error(status, data, "application/json")

proc jsonError*(_: typedesc[RestApiResponse],
                rmsg: RestErrorMessage): RestApiResponse =
  let data = withRestJsonWriter(w, string):
    w.writeObject:
      w.writeField("code", rmsg.code)
      w.writeField("message", rmsg.message)
      w.writeField("stacktraces", rmsg.stacktraces)

  RestApiResponse.error(rmsg.code.toHttpCode().get(), data, "application/json")

proc jsonErrorList*(_: typedesc[RestApiResponse],
                    status: HttpCode = Http200,
                    msg: string = "", failures: auto): RestApiResponse =
  let data = withRestJsonWriter(w, string):
    w.writeObject:
      w.writeField("code", int(status.toInt()))
      w.writeField("message", msg)
      w.writeField("failures", failures)

  RestApiResponse.error(status, data, "application/json")

proc sszResponsePlain*(
    _: typedesc[RestApiResponse],
    res: seq[byte],
    hasRestAllowedOrigin: bool): RestApiResponse =
  let headers = ethHeaders(hasRestAllowedOrigin)
  RestApiResponse.response(
    res, Http200, "application/octet-stream", headers = headers)

proc sszResponse*(
    _: typedesc[RestApiResponse],
    data: auto,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    res = SSZ.encode(data)
    headers = ethHeaders(hasRestAllowedOrigin)
  RestApiResponse.response(
    res, Http200, "application/octet-stream", headers = headers)

proc sszResponse*(
    _: typedesc[RestApiResponse],
    data: auto,
    isBlinded: bool,
    executionValue: UInt256,
    consensusValue: UInt256,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    res = SSZ.encode(data)
    headers = ethHeaders(
      isBlinded, executionValue, consensusValue, hasRestAllowedOrigin)
  RestApiResponse.response(
    res, Http200, "application/octet-stream", headers = headers)

proc decodeBody*(T: typedesc, body: ContentBody): Result[T, cstring] =
  if body.contentType != ApplicationJsonMediaType:
    return err("Unsupported content type")

  try:
    ok RestJson.decode(body.data, T)
  except SerializationError as exc:
    err("Unable to deserialize data")

proc decodeBodyJsonOrSsz*(T: typedesc,
                          body: ContentBody): Result[T, RestErrorMessage] =
  if body.contentType == ApplicationJsonMediaType:
    try:
      ok RestJson.decode(body.data, T)
    except SerializationError as exc:
      debug "Failed to decode JSON data",
            err = exc.formatMsg("<data>"),
            data = string.fromBytes(body.data)
      err(RestErrorMessage.init(Http400, UnableDecodeError,
                                [exc.formatMsg("<data>")]))
  elif body.contentType == OctetStreamMediaType:
    try:
      ok SSZ.decode(body.data, T)
    except SerializationError as exc:
      err(RestErrorMessage.init(Http400, UnableDecodeError,
                                [exc.formatMsg("<data>")]))
  else:
    err(RestErrorMessage.init(Http415, InvalidContentTypeError,
                              [$body.contentType]))

proc encodeBytes*[T: EncodeTypes](value: T,
                                  contentType: string): RestResult[seq[byte]] =
  case contentType
  of "application/json":
    ok block:
      withRestJsonWriter(w, seq[byte]):
        w.writeValue(value)
  else:
    err("Content-Type not supported")

proc decodeBytes*[T: DecodeTypes](
       t: typedesc[T],
       value: openArray[byte],
       contentType: Opt[ContentTypeData]
     ): RestResult[T] =

  let mediaType =
    if contentType.isNone():
      ApplicationJsonMediaType
    else:
      if isWildCard(contentType.get().mediaType):
        return err("Incorrect Content-Type")
      contentType.get().mediaType

  if mediaType == ApplicationJsonMediaType:
    try:
      ok RestJson.decode(value, T)
    except SerializationError as exc:
      err("Serialization error")
  else:
    err("Content-Type not supported")

func encodeString*(value: string): RestResult[string] =
  ok(value)

func encodeString*(value: uint64): RestResult[string] =
  ok(Base10.toString(uint64(value)))

func decodeString*(t: typedesc[PeerStateKind],
                   value: string): Result[PeerStateKind, cstring] =
  case value
  of "disconnected":
    ok(PeerStateKind.Disconnected)
  of "connecting":
    ok(PeerStateKind.Connecting)
  of "connected":
    ok(PeerStateKind.Connected)
  of "disconnecting":
    ok(PeerStateKind.Disconnecting)
  else:
    err("Incorrect peer state value")

func encodeString*(value: PeerStateKind): Result[string, cstring] =
  case value
  of PeerStateKind.Disconnected:
    ok("disconnected")
  of PeerStateKind.Connecting:
    ok("connecting")
  of PeerStateKind.Connected:
    ok("connected")
  of PeerStateKind.Disconnecting:
    ok("disconnecting")

func decodeString*(t: typedesc[PeerDirectKind],
                   value: string): Result[PeerDirectKind, cstring] =
  case value
  of "inbound":
    ok(PeerDirectKind.Inbound)
  of "outbound":
    ok(PeerDirectKind.Outbound)
  else:
    err("Incorrect peer direction value")

func encodeString*(value: PeerDirectKind): Result[string, cstring] =
  case value
  of PeerDirectKind.Inbound:
    ok("inbound")
  of PeerDirectKind.Outbound:
    ok("outbound")

func encodeString*(peerid: PeerId): Result[string, cstring] =
  ok($peerid)

func decodeString*(t: typedesc[string],
                   value: string): Result[string, cstring] =
  ok(value)

func decodeString*(t: typedesc[uint64],
                   value: string): Result[uint64, cstring] =
  Base10.decode(uint64, value)

func decodeString*(t: typedesc[PeerId],
                   value: string): Result[PeerId, cstring] =
  PeerId.init(value)
