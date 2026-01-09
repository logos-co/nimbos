# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# This module exports SSZ.encode and SSZ.decode for spec types - don't use
# ssz_serialization directly! To bypass root updates, use `readSszBytes`
# without involving SSZ!
import
  ssz_serialization,
  ./datatypes/base

export base, ssz_serialization
