# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option, this file may not be copied, modified, or distributed except according to those terms.

## Small helpers shared by the zk test suites.

{.push raises: [].}

import
  std/[monotimes, os],
  results

export results

proc uniqueTmpDir*(tag: string): string =
  ## Per-test unique directory under the system temp dir. Never removed;
  ## skipping teardown keeps test bodies focused on the assertion.
  getTempDir() / ("nimbos_" & tag & "_" & $getMonoTime().ticks)

func accepts*[E](r: Result[bool, E]): bool =
  ## A verifier result that is `ok(true)`.
  r.isOk and r.valueOr(false)

func rejects*[E](r: Result[bool, E]): bool =
  ## A verifier result that is `ok(false)`: a well-formed but invalid proof.
  r.isOk and not r.valueOr(true)

{.pop.}
