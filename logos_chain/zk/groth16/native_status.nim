# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Fixed-size status message shared by the native prover bindings. Plain
## data, so it can travel across threads inside an output object.

{.push raises: [], gcsafe.}

const MessageLen* = 256
  ## Size of the C status message buffers (circuits FFI and rapidsnark).

type
  NativeMessage* = array[MessageLen, char]

  NativeFailure*[K] = object
    ## Error kind plus the C message.
    kind*: K
    message*: NativeMessage

template cbuf*(message: var NativeMessage): cstring =
  ## The buffer as the `char*` the C side writes into.
  cast[cstring](addr message[0])

func messageString*(message: NativeMessage): string =
  ## The NUL-terminated C message as a Nim string.
  var text: string
  for c in message:
    if c == '\0':
      break
    text.add(c)
  text

{.pop.}
