# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/uri,
  chronos, chronos/apps,
  presto/common

type
  ClientResponse* = object
    status*: int
    data*: string
    headers*: HttpTable

func init(
    t: typedesc[ClientResponse], status: int, data: string, headers: HttpTable
): ClientResponse =
  ClientResponse(status: status, data: data, headers: headers)

proc httpClient*(
    server: TransportAddress,
    meth: HttpMethod,
    url: string,
    body: string,
    ctype = "",
    accept = "",
    encoding = "",
    length = -1
): Future[ClientResponse] {.async.} =
  var request = $meth & " " & $parseUri(url) & " HTTP/1.1\r\n"
  request.add("Host: " & $server & "\r\n")
  if encoding.len == 0:
    if length >= 0:
      request.add("Content-Length: " & $length & "\r\n")
    else:
      request.add("Content-Length: " & $body.len & "\r\n")
  if ctype.len > 0:
    request.add("Content-Type: " & ctype & "\r\n")
  if accept.len > 0:
    request.add("Accept: " & accept & "\r\n")
  if encoding.len > 0:
    request.add("Transfer-Encoding: " & encoding & "\r\n")
  request.add("\r\n")

  if body.len > 0:
    request.add(body)

  var headersBuf = newSeq[byte](4096)
  let transp = await connect(server)
  discard await transp.write(request)
  let rlen = await transp.readUntil(addr headersBuf[0], headersBuf.len, HeadersMark)
  headersBuf.setLen(rlen)
  let resp = parseResponse(headersBuf, true)
  doAssert resp.success()

  let headers =
    block:
      var res = HttpTable.init()
      for key, value in resp.headers(headersBuf):
        res.add(key, value)
      res

  let clen = resp.contentLength()
  doAssert clen >= 0

  let cresp =
    if clen > 0:
      var dataBuf = newString(clen)
      await transp.readExactly(addr dataBuf[0], dataBuf.len)
      ClientResponse.init(resp.code, dataBuf, headers)
    else:
      ClientResponse.init(resp.code, "", headers)

  await transp.closeWait()
  cresp

{.pop.}

