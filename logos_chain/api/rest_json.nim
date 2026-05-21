# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[macros, strformat, strutils],
  results,
  stew/[base10, byteutils],
  stint,
  faststreams/textio,
  json_serialization,
  json_serialization/pkg/results,
  ./types

export
  results, json_serialization, results,
  types, stint

## In this format, we must always set `allowUnknownFields = true` in the
## decode calls in order to conform the following spec:
##
## All JSON responses return the requested data under a data key in the top
## level of their response.  Additional metadata may or may not be present
## in other keys at the top level of the response, dependent on the endpoint.
## The rules that require an increase in version number are as follows:
##
## - no field that is listed in an endpoint shall be removed without an increase
##   in the version number
##
## - no field that is listed in an endpoint shall be altered in terms of format
##   (e.g. from a string to an array) without an increase in the version number
##
## This also means that when new fields are introduced to the object definitions
## below, one must use the `Opt[T]` type so as not to trigger `requiresAllFields`.

createJsonFlavor RestJson,
  automaticObjectSerialization = false,
  requireAllFields = true,
  omitOptionalFields = true,
  allowUnknownFields = true

#!fmt: off
RestJson.useDefaultSerializationFor(
  DataEnclosedObject,
  DataMetaEnclosedObject,
  DataOptimisticAndFinalizedObject,
  DataOptimisticObject,
  EmptyBody,
  GetSpecVCResponse,
  RestChainHeadV2,
  RestIndexedErrorMessage,
  RestIndexedErrorMessageItem,
  RestMetadata,
  RestNetworkIdentity,
  RestNimbusTimestamp1,
  RestNimbusTimestamp2,
  RestNode,
  RestNodePeer,
  RestNodeVersion,
  RestPeerCount
)
#!fmt: on

# transplant from another module
type
  RestErrorMessage* = object
    ## https://github.com/ethereum/beacon-APIs/blob/v2.4.0/types/http.yaml#L130
    code*: int
    message*: string
    stacktraces*: Opt[seq[string]]

  RestIndexedErrorMessage* = object
    ## https://github.com/ethereum/beacon-APIs/blob/v2.4.0/types/http.yaml#L145
    code*: int
    message*: string
    failures*: seq[RestIndexedErrorMessageItem]

  RestIndexedErrorMessageItem* = object
    index*: int
    message*: string

  RestJsonWriter = RestJson.Writer()
  RestJsonReader = RestJson.Reader()

{.pragma: reader, raises: [IOError, SerializationError].}
{.pragma: writer, raises: [IOError].}

## https://github.com/ethereum/beacon-APIs/blob/v3.1.0/types/primitive.yaml#L57
proc write0xHex*(w: var RestJsonWriter, value: openArray[byte]) {.writer.} =
  w.streamElement(s):
    s.write("\"0x")
    s.writeHex(value)
    s.write('"')

# TODO
# Tuples are widely used in the responses of the REST server
# If we switch to concrete types there, it would be possible
# to remove this overly generic definition.
template writeValue*(w: RestJsonWriter, value: tuple) =
  writeRecordValue(w, value)

## https://github.com/ethereum/beacon-APIs/blob/v3.1.0/types/primitive.yaml#L31
proc writeValue*(
    w: var RestJsonWriter, value: uint64 | uint32 | uint16 | uint8
) {.writer.} =
  w.streamElement(s):
    s.write('"')
    s.writeText(value)
    s.write('"')

proc readValue*[T: uint64 | uint32 | uint16 | uint8](
    r: var RestJsonReader, value: var T
) {.reader.} =
  let svalue = r.readValue(string)
  value = Base10.decode(T, svalue).valueOr:
    r.raiseUnexpectedValue($error & ": " & svalue)

proc writeValue*(w: var RestJsonWriter, value: RestReward) {.writer.} =
  w.streamElement(s):
    s.write('"')
    s.writeText(int64(value))
    s.write('"')

proc readValue*(r: var RestJsonReader, value: var RestReward) {.reader.} =
  let svalue = r.readValue(string)
  if svalue.startsWith("-"):
    let res = Base10.decode(uint64, svalue.toOpenArray(1, len(svalue) - 1)).valueOr:
      r.raiseUnexpectedValue($error & ": " & svalue)
    if res > uint64(high(int64)):
      r.raiseUnexpectedValue("Integer value overflow " & svalue)
    value = RestReward(-int64(res))
  else:
    let res = Base10.decode(uint64, svalue).valueOr:
      r.raiseUnexpectedValue($error & ": " & svalue)
    if res > uint64(high(int64)):
      r.raiseUnexpectedValue("Integer value overflow " & svalue)
    value = RestReward(int64(res))

proc writeValue*(w: var RestJsonWriter, value: RestNumeric) {.writer.} =
  w.streamElement(s):
    s.writeText(int(value))

proc readValue*(r: var RestJsonReader, value: var RestNumeric) {.reader.} =
  if r.tokKind == JsonValueKind.String:
    # Nimbus earlier than v23.11.0 erroneously used a string in some number
    # fields - provide backwards compatibilty..
    let svalue = r.readValue(string)
    try:
      value = RestNumeric(parseInt(svalue))
    except ValueError:
      r.raiseUnexpectedValue("Expected number/string")
  else:
    value = RestNumeric(r.parseInt(int))

proc writeValue*(w: var RestJsonWriter, value: UInt256) {.writer.} =
  w.writeValue(toString(value))

proc readValue*(r: var RestJsonReader, value: var UInt256) {.reader.} =
  let svalue = r.readValue(string)
  try:
    value = parse(svalue, UInt256, 10)
  except ValueError:
    r.raiseUnexpectedValue("UInt256 value should be a valid decimal string")

proc readValue*(
    r: var RestJsonReader,
    value: var RestWithdrawalPrefix,
) {.reader.} =
  try:
    hexToByteArray(r.readValue(string), distinctBase(value))
  except ValueError:
    r.raiseUnexpectedValue(
      &"Expected a valid hex string with {distinctBase(value).len()} bytes"
    )

template unrecognizedFieldWarning(fieldNameParam, typeNameParam: string) =
  # TODO: There should be a different notification mechanism for informing the
  #       caller of a deserialization routine for unexpected fields.
  #       The chonicles import in this module should be removed.
  trace "JSON field not recognized by the current version of Nimbos. Consider upgrading",
    fieldName = fieldNameParam, typeName = typeNameParam

template unrecognizedFieldIgnore() =
  discard r.readValue(JsonString)

proc writeValue*(w: var RestJsonWriter, value: RestErrorMessage) {.writer.} =
  w.writeObject:
    w.writeField("code", value.code)
    w.writeField("message", value.message)
    w.writeField("stacktraces", value.stacktraces)
