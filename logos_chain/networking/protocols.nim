# nimbos
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Logos Chain libp2p application protocol IDs.
## Spec: https://github.com/logos-co/logos-lips/blob/435a6f183a92b871473d80a720b427f70cbf1b68/docs/blockchain/draft/p2p-network.md#peer-discovery

{.push raises: [], gcsafe.}

import
  libp2p/[switch, peerinfo, errors, crypto/crypto],
  libp2p/protocols/identify,
  libp2p/protocols/kademlia,
  ../conf

type
  MountedProtocols* = object
    kad*: KadDHT
    identify*: Identify
      ## Autonomous protocol managed internally by the switch after mounting.

const
  LogosIdentifyMainnet = "/logos-blockchain/identify/1.0.0"
  LogosIdentifyTestnet = "/logos-blockchain-testnet/identify/1.0.0"
  LogosKadMainnet = "/logos-blockchain/kad/1.0.0"
  LogosKadTestnet = "/logos-blockchain-testnet/kad/1.0.0"

func identifyCodec(network: LogosNetworkKind): string =
  case network
  of Mainnet: LogosIdentifyMainnet
  of Testnet: LogosIdentifyTestnet

func kadCodec*(network: LogosNetworkKind): string =
  case network
  of Mainnet: LogosKadMainnet
  of Testnet: LogosKadTestnet

proc mountIdentifyProtocol*(
    sw: Switch, peerInfo: PeerInfo, network: LogosNetworkKind
): Identify {.raises: [LPError].} =
  let codec = identifyCodec(network)
  let ident = Identify.new(peerInfo)
  ident.codec = codec
  ident.codecs = @[codec]
  sw.mount(ident)
  ident

proc mountKadProtocol*(
    sw: Switch, network: LogosNetworkKind, rng: Rng
): KadDHT {.raises: [LPError].} =
  let codec = kadCodec(network)
  let kad = KadDHT.new(sw, rng = rng, codec = codec)
  kad.codecs = @[codec]
  sw.mount(kad)
  kad

{.pop.}
