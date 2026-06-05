AllTests
===
## CryptarchiaState init
```diff
+ empty init has no utxos                                                                    OK
+ init from empty UtxoStore equivalent to empty init                                         OK
+ init from seed populates correctly                                                         OK
+ two empty states are equal                                                                 OK
```
## CryptarchiaState reads
```diff
+ latestUtxos returns the inner store                                                        OK
+ root delegates to UtxoStore                                                                OK
```
## DynamicMerkleTree empty
```diff
+ empty root equals emptySubtreeRoot(TreeDepth)                                              OK
+ empty trees are equal                                                                      OK
+ fresh tree has empty root                                                                  OK
```
## DynamicMerkleTree insert / path / verify
```diff
+ deterministic root: same inserts in two fresh trees → equal roots                        OK
+ many inserts: every leaf has a verifying path                                              OK
+ persistence: parent tree unchanged by child insert                                         OK
+ persistence: parent tree unchanged by child remove                                         OK
+ single insert assigns index 0 and produces a valid path                                    OK
+ single-item path: every sibling is (Right, emptySubtreeRoot[h])                            OK
+ two-item path: adjacent leaves carry each other's digest at level 0                        OK
```
## DynamicMerkleTree remove + hole reuse (smallest-first)
```diff
+ insert-all then remove-all returns to empty-tree root                                      OK
+ remove nulls the leaf and drops len                                                        OK
+ remove out of bounds panics                                                                OK
+ root consistency: remove + reinsert same item at same index = same root                    OK
+ smallest hole first: next insert lands at the smallest free index                          OK
```
## HashTrieMap $
```diff
+ empty map stringifies to {}                                                                OK
+ multi-entry contains all (key, value) pairs                                                OK
+ single-entry map                                                                           OK
```
## HashTrieMap basics
```diff
+ getOrDefault returns default(V) when missing                                               OK
+ init creates empty map                                                                     OK
+ insert many entries; all retrievable                                                       OK
+ insert stores entry; len grows                                                             OK
+ insert then remove all empties the map                                                     OK
+ insert with existing key replaces value; len unchanged                                     OK
+ remove drops a single entry                                                                OK
+ remove of absent key is idempotent                                                         OK
+ subscript raises KeyError on missing                                                       OK
```
## HashTrieMap collisions
```diff
+ collapsing collision down to one entry leaves survivor accessible                          OK
+ insert with different hash splits collision into a branch chain                            OK
+ remove one entry from a 3-way collision                                                    OK
+ stress: many entries packed into a small number of hash buckets                            OK
+ two keys with same hash and different identity coexist                                     OK
```
## HashTrieMap diverse types
```diff
+ object values                                                                              OK
+ seq[byte] keys                                                                             OK
+ string keys                                                                                OK
```
## HashTrieMap equality
```diff
+ different lengths are unequal                                                              OK
+ empty maps are equal                                                                       OK
+ remove restores equality                                                                   OK
+ same content, different insertion order                                                    OK
+ same content, same insertion order                                                         OK
+ same keys, different values are unequal                                                    OK
```
## HashTrieMap fuzz
```diff
+ behaves like std/tables.Table under random insert/remove                                   OK
```
## HashTrieMap iteration
```diff
+ iteration covers collision buckets                                                         OK
+ iteration covers exactly the current key set after random churn                            OK
+ iteration on empty map yields nothing                                                      OK
+ iteration order is deterministic for the same insert sequence                              OK
+ keys yields all distinct keys                                                              OK
+ pairs yields every entry exactly once                                                      OK
+ values yields all values (with multiplicity)                                               OK
```
## HashTrieMap persistence
```diff
+ many versions coexist independently                                                        OK
+ mutating one version provably leaves the other unchanged                                   OK
+ old map unaffected after insert                                                            OK
+ old map unaffected after remove                                                            OK
```
## HashTrieMap scale and structure
```diff
+ 10k entries: full insert / lookup / iterate / remove cycle                                 OK
+ 32 distinct slot-0 hashes fill a root branch (all children occupied)                       OK
+ remove then reinsert yields a map equal to original                                        OK
```
## HashTrieMap toHashTrieMap
```diff
+ builds from a table-literal of pairs                                                       OK
+ duplicate keys: last value wins                                                            OK
+ empty input yields an empty map                                                            OK
```
## HashTrieMap withValue
```diff
+ single-body form runs body only when key is present                                        OK
+ two-body form covers both branches                                                         OK
```
## LedgerState constructors and reads
```diff
+ fromUtxos with N utxos → state populated                                                 OK
+ fromUtxos with empty seq → empty state                                                   OK
```
## Ledger[Id] map ops
```diff
+ commitUpdate overwrites                                                                    OK
+ init seeds one (id, state); state(id) returns Some                                         OK
+ pruneStateAt removes existing, returns true; missing returns false                         OK
```
## Logos REST node API stub endpoints
```diff
+ GET /cryptarchia/blocks returns empty list                                                 OK
+ GET /cryptarchia/events/blocks/stream returns empty body                                   OK
+ GET /cryptarchia/headers returns empty list                                                OK
+ GET /cryptarchia/info returns empty object                                                 OK
+ GET /cryptarchia/lib-stream returns empty body                                             OK
+ GET /mantle/metrics returns empty object                                                   OK
+ GET /network/info returns empty object                                                     OK
+ GET /wallet/{public_key}/balance rejects invalid public_key                                OK
+ GET /wallet/{public_key}/balance returns empty object                                      OK
+ POST /leader/claim returns empty object                                                    OK
+ POST /mantle/status returns empty list                                                     OK
+ POST /mempool/add/tx returns empty body                                                    OK
+ POST /sdp/activity returns empty list                                                      OK
+ POST /sdp/declaration returns wrapped empty string                                         OK
+ POST /sdp/withdrawal returns empty object                                                  OK
+ POST /storage/block returns empty quoted string                                            OK
+ POST /test/membership/update returns empty object                                          OK
+ POST /wallet/transactions/transfer-funds returns empty object                              OK
+ validateBeaconApiQueries accepts valid wallet public_key with and without 0x               OK
+ validateBeaconApiQueries rejects invalid wallet public_key lengths and characters          OK
```
## P2P stack — GossipSub topics (Logos Chain wire topics)
```diff
  GossipSub: subscribes and publishes /logos-blockchain-testnet/cryptarchia/1.0.0 (testnet)  Skip
  GossipSub: subscribes and publishes /logos-blockchain-testnet/mempool/1.0.0 (testnet)      Skip
  GossipSub: subscribes and publishes /logos-blockchain/cryptarchia/1.0.0 (mainnet)          Skip
  GossipSub: subscribes and publishes /logos-blockchain/mempool/1.0.0 (mainnet)              Skip
```
## P2P stack — NAT and AutoNAT v2
```diff
  AutoNAT v2 client uses /libp2p/autonat/2/dial-request toward reachable peers               Skip
  AutoNAT v2 server responds on /libp2p/autonat/2/dial-back when node is public              Skip
```
## P2P stack — bootstrap and discovery
```diff
+ After bootstrap: libp2p QUIC session stays up (decentralized DHT deferred)                 OK
+ Bootstrap dial: node connects from /ip4/.../udp/.../p2p/{peerId} bootstrap multiaddr       OK
+ Bootstrap multiaddr: parseBootstrapAddress accepts /dns4/.../udp/.../quic-v1/p2p/...       OK
  Kademlia: DHT protocol registered as /logos-blockchain-testnet/kad/1.0.0 (testnet)         Skip
  Kademlia: DHT protocol registered as /logos-blockchain/kad/1.0.0 (mainnet)                 Skip
```
## P2P stack — on-the-wire encoding
```diff
  Network Wire Format: payloads on negotiated streams follow Logos Chain wire format spec    Skip
```
## P2P stack — protocol negotiation and Identify
```diff
  Identify exchange: peers report protocol support compatible with NAT / AutoNAT discovery n Skip
  Identify: handler registered for /logos-blockchain-testnet/identify/1.0.0 (testnet)        Skip
  Identify: handler registered for /logos-blockchain/identify/1.0.0 (mainnet)                Skip
  Multistream: connection negotiates an application protocol by exact protocol ID string     Skip
```
## P2P stack — transport and reachability (Logos Chain / libp2p spec)
```diff
+ Lifecycle: network start and stop release listeners and pending dials cleanly              OK
+ Public advertisement: reachable multiaddr matches /{ip}/udp/{port}/quic-v1/p2p/{peer_id}   OK
+ QUIC quic-v1 listen: switch binds and accepts on configured listen multiaddr               OK
```
## PeerPool testing suite
```diff
+ Access peers by key test                                                                   OK
+ Acquire from empty pool                                                                    OK
+ Acquire/Sorting and consistency test                                                       OK
+ Custom filters test                                                                        OK
+ Delete peer on release text                                                                OK
+ Iterators test                                                                             OK
+ Peer lifetime test                                                                         OK
+ Safe/Clear test                                                                            OK
+ Score check test                                                                           OK
+ Space tests                                                                                OK
+ addPeer() test                                                                             OK
+ addPeerNoWait() test                                                                       OK
+ deletePeer() test                                                                          OK
```
## Poseidon2Hasher (BN254)
```diff
+ digest([0, 1, 2])                                                                          OK
+ digest([0])                                                                                OK
+ digest([1])                                                                                OK
+ digest([2])                                                                                OK
```
## Utxo.id
```diff
+ cross-language reference vector matches Rust `test_note_id`                                OK
+ deterministic: same Utxo data → same NoteId                                              OK
+ different outputIndex → different NoteId                                                 OK
+ different pk → different NoteId                                                          OK
+ different value → different NoteId                                                       OK
+ round-trip: id.toBytes ↔ NoteId.fromBytes                                                OK
```
## UtxoStore empty
```diff
+ fresh store is empty                                                                       OK
+ lookups on empty store return none                                                         OK
+ two empty stores are equal                                                                 OK
```
## UtxoStore insert / lookup / path
```diff
+ duplicate insert panics                                                                    OK
+ many inserts: each assigns the next contiguous leaf index                                  OK
+ persistence: parent store unchanged by child insert                                        OK
+ single insert: contains/get/path all reflect the new entry                                 OK
```
## UtxoStore remove
```diff
+ insert-then-remove returns to empty root                                                   OK
+ remove + reinsert lands at the freed leaf index                                            OK
+ remove of absent key returns NotFound                                                      OK
+ remove returns the stored Utxo and drops the entry                                         OK
```
## UtxoStore root determinism / mixed ops
```diff
+ interleaved insert / remove / insert preserves size and membership                         OK
+ same insertions on two fresh stores yield equal root                                       OK
```
## UtxoStore utxos() accessor
```diff
+ exposes the underlying NoteId → (Utxo, leafIndex) map                                    OK
```
## chain/genesis
```diff
+ createGenesisBlock builds expected header/envelope from deployment settings                OK
+ createGenesisBlock from genesisState matches createGenesisBlock from signedMantleTx        OK
+ createGenesisBlock wraps a minimal signed mantle tx                                        OK
```
## core/crypto/hashing
```diff
+ blake2b256Hash is deterministic                                                            OK
  generateGroth16Proof succeeds when Groth16 fixtures are available                          Skip
  generateZkSignature placeholder is currently skipped                                       Skip
  poseidon2Hash is deterministic and input-sensitive                                         Skip
+ prngBlock is deterministic for same seed and index                                         OK
+ prngBytes empty yields empty                                                               OK
```
## core/crypto/types
```diff
+ encodeFieldElement round-trips canonical LE bytes                                          OK
+ encodeLe explicit generic and inferred forms match                                         OK
+ encodeLe infers output width from unsigned input type                                      OK
+ encodeLe uint64 little-endian                                                              OK
+ encodeU16LeLenPrefixed length then bytes                                                   OK
+ encodeU32LeLenPrefixed length then bytes                                                   OK
```
## core/mantle/operations
```diff
+ Mantle opcode constants match expected wire values                                         OK
+ create*Op constructors set opcode and payload kind                                         OK
+ decodeChannelDeposit and decodeChannelWithdraw roundtrip encoders                          OK
+ decodeOps roundtrips encodeOps                                                             OK
+ defaultOpForOpcode creates matching opcode and payload                                     OK
+ defaultOpProofForOpcode matches opcode proof kind                                          OK
+ encodeChannelDeposit and encodeChannelWithdraw include expected prefixes                   OK
+ encodeOps prefixes op count and includes opcode                                            OK
+ expectedOpProofKindForOpcode matches op families                                           OK
+ opPayloadToOpcode round-trips kind                                                         OK
```
## core/mantle/primitives
```diff
+ References is MaxBlockTxs of Hash32                                                        OK
+ decodeLocator roundtrips encodeLocator                                                     OK
+ decodeMetadata roundtrips encodeMetadata                                                   OK
+ decodeOpcode roundtrips encodeOpcode                                                       OK
+ decodeValue roundtrips encodeValue                                                         OK
+ encodeMetadata empty is length 0 u32 le                                                    OK
+ encodeOpcode is single byte                                                                OK
+ encodeValue is uint64 LE                                                                   OK
+ primitive constants match expected values                                                  OK
```
## core/mantle/proofs
```diff
+ decodeOpsProofs roundtrips encodeOpsProofs                                                 OK
+ encodeOpsProofs accepts proofs length <= op count                                          OK
+ proofType maps concrete proof variants to canonical families                               OK
```
## core/mantle/tx_hashing
```diff
+ mantleTxHash is deterministic                                                              OK
+ mantleTxHash is sensitive to tx bytes                                                      OK
```
## core/mantle/tx_types
```diff
+ decodeMantleTx roundtrips encodeMantleTx                                                   OK
+ decodeSignedMantleTx roundtrips encodeSignedMantleTx                                       OK
```
## core/sdp/state
```diff
+ DeclarationInfo fields are default-zero                                                    OK
+ LockedNote starts with empty declaration set                                               OK
+ validateLocator accepts valid locator and rejects oversized ones                           OK
```
## core/types
```diff
+ blockId is deterministic for same header                                                   OK
+ blockId returns 32-byte hash                                                               OK
+ createBlockRoot changes when tx order changes                                              OK
+ createBlockRoot odd leaf count uses zero padding not duplicate last                        OK
+ createBlockRoot returns zero hash for empty tx list                                        OK
+ createBlockRoot single tx equals that tx hash                                              OK
+ initBlock accepts empty tx list                                                            OK
```
## deployment-settings
```diff
+ deployment-settings: mantle_tx ops and ops_proofs are block sequences                      OK
+ deploymentSettingsFromYaml: typed fields and genesis subtree on minimal valid              OK
+ loadDeploymentSettings fails for incomplete YAML                                           OK
+ loadDeploymentSettings fails for malformed YAML file                                       OK
+ loadDeploymentSettings fails for missing file with clear message                           OK
+ loadDeploymentSettings validates canonical YAML                                            OK
+ parse and validate canonical deployment-settings YAML                                      OK
+ parseDeploymentSettings: empty time.slot_duration                                          OK
+ parseDeploymentSettings: missing required paths                                            OK
+ parseDeploymentSettings: network not a mapping                                             OK
+ parseDeploymentSettings: non-scalar leaf cryptarchia.gossipsub_protocol                    OK
+ parseDeploymentSettings: non-scalar leaf mempool.pubsub_topic                              OK
+ parseDeploymentSettings: non-scalar leaf network.chain_sync_protocol_name                  OK
+ parseDeploymentSettings: non-scalar leaf network.identify_protocol_name                    OK
+ parseDeploymentSettings: non-scalar leaf network.kademlia_protocol_name                    OK
+ parseDeploymentSettings: top-level must be mapping (scalar root)                           OK
+ parseDeploymentSettings: top-level must be mapping (sequence root)                         OK
+ parseDeploymentSettingsYaml: empty stream                                                  OK
+ parseDeploymentSettingsYaml: invalid YAML syntax                                           OK
+ parseDeploymentSettingsYaml: multiple documents rejected                                   OK
+ validateDeploymentSettings: all checks pass for minimal valid                              OK
+ validateDeploymentSettings: empty blend.common.protocol_name                               OK
+ validateDeploymentSettings: empty kademlia string                                          OK
+ validateDeploymentSettings: protocol without leading slash                                 OK
+ validateDeploymentSettings: zero cryptarchia slot coeff denominator                        OK
+ yamlGetMap: missing key returns none                                                       OK
+ yamlGetMap: non-mapping node returns none                                                  OK
```
## devnet genesis mantle_tx block root
```diff
+ deployment genesis block id matches devnet header preimage                                 OK
+ devnet genesis mantle tx encoding and hashes match fixed vectors                           OK
+ genesis fixture single-tx block root matches deployment header.block_root                  OK
```
## ledger/pol_verifier
```diff
+ genesis sentinel accepted (no Groth16 invocation)                                          OK
+ real fixture accepted end-to-end                                                           OK
+ rejects entropyContribution >= BN254 modulus                                               OK
+ rejects mutated leaderKey                                                                  OK
+ rejects wrong epochNonce                                                                   OK
+ rejects wrong slot                                                                         OK
```
## prepareUpdate
```diff
+ empty tx list → state unchanged, no commit                                               OK
+ happy path with one transfer + commit                                                      OK
+ multi-block IBD: 3 prepare+commit cycles                                                   OK
+ parent missing → ParentNotFound                                                          OK
+ unbalanced tx → UnbalancedTransaction                                                    OK
```
## tryApplyHeader
```diff
+ genesis-sentinel proof returns state unchanged                                             OK
+ returns InvalidProof when verifier rejects                                                 OK
+ returns VerifierNotInitialised when VK singleton missing                                   OK
```
## tryApplyTransfer — balance + chain
```diff
+ chain of txs: tx2 spends outputs created by tx1                                            OK
+ no outputs → balance equals full input value                                             OK
+ outputs exceed input → returns negative balance                                          OK
+ unbalanced (input > output) returns positive balance                                       OK
```
## tryApplyTransfer — error paths
```diff
+ bad signature → InvalidProof                                                             OK
+ locked input → LockedNote                                                                OK
+ missing input → InvalidNote (three shapes)                                               OK
+ zero-value output → ZeroValueNote                                                        OK
```
## tryApplyTransfer — happy paths
```diff
+ 1-in / 1-out same value                                                                    OK
+ multi-input combine (2 inputs, 1 output)                                                   OK
+ split (1 input, 3 outputs)                                                                 OK
```
## tryApplyTransfer — persistence
```diff
+ parent state unchanged when child applies a transfer                                       OK
```
## tryApplyTx — error paths
```diff
+ Transfer op with wrong proof kind → InvalidProof                                         OK
+ non-Transfer op → UnsupportedOp                                                          OK
+ ops/proofs count mismatch → InvalidProof                                                 OK
```
## tryApplyTx — happy path
```diff
+ single OpTransfer (balanced) returns balance == 0                                          OK
```
## tryApplyTx — multi-op
```diff
+ two balanced Transfer ops → balance == 0, both applied                                   OK
+ two ops, second has wrong proof kind → InvalidProof                                      OK
```
## tryApplyTxns
```diff
+ balanced tx → state advances                                                             OK
+ overspending (input > output) → UnbalancedTransaction                                    OK
+ underspending (output > input) → UnbalancedTransaction                                   OK
```
## zk/circuits — path derivations
```diff
+ circuitsVersionPath joins <dir>/VERSION                                                    OK
+ polVerificationKeyPath joins <dir>/pol/verification_key.json                               OK
```
## zk/circuits — verifyCircuitsVersion
```diff
+ accepts VERSION with trailing newline                                                      OK
+ accepts matching VERSION                                                                   OK
+ rejects dir without VERSION                                                                OK
+ rejects mismatched VERSION                                                                 OK
+ rejects missing dir                                                                        OK
```
## zk/groth16/verifier
```diff
+ Q1 canary — verify result unchanged with non-zero beta1/delta1                           OK
+ accepts canonical PoL test vector                                                          OK
+ rejects bit-flipped proof                                                                  OK
+ rejects garbage proof bytes                                                                OK
+ rejects mutated public input                                                               OK
```
## zk/groth16/vk_json
```diff
+ parseVk accepts canonical PoL VK fixture                                                   OK
+ parseVk rejects malformed JSON                                                             OK
+ toVKey rejects non-decimal field element                                                   OK
+ toVKey rejects off-curve G1 point                                                          OK
+ toVKey rejects wrong curve                                                                 OK
+ toVKey rejects wrong protocol                                                              OK
```
## zk/pol — loadVk
```diff
+ accepts canonical fixture                                                                  OK
+ rejects JSON with wrong protocol                                                           OK
+ rejects garbage JSON                                                                       OK
+ rejects missing file                                                                       OK
```
## zk/pol — verify
```diff
+ accepts canonical PoL test vector                                                          OK
+ double initVk returns VkAlreadyLoaded                                                      OK
+ rejects mutated entropyContribution                                                        OK
+ rejects swapped slot/epochNonce                                                            OK
+ rejects when VK singleton not installed                                                    OK
```
