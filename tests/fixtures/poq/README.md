# poq test fixtures

nimbos ships only the proof-of-quota verifier — it has no Nim-side prover
that could generate a proof on the fly during tests. These files are
committed fixtures (reference-prover output) so the Nim verifier
(`tests/zk/test_poq.nim`, `tests/ledger/test_poq_verifier.nim`) has
something to verify against.

One fixture per circuit branch. The three proofs use different selector
values (core = 0, leader = 1, pow = 2); a verifier cannot tell them
apart, and the tests use that to prove the verifier is branch-blind.

| File | Format |
|---|---|
| `verification_key.json` | snarkjs VK from circuits-bundle |
| `proof_<branch>.bin` | 160-byte wire `ProofOfQuota`: key nullifier (32, Fr LE) ‖ compressed proof (128) |
| `public_<branch>.json` | flat 12-element array in circuit signal order |

Signal order (spec §Public values pins it):
`[key_nullifier, core_quota, leader_quota, core_root, pow_quota,
pol_ledger_aged, K_part_one, K_part_two, pow_blend_difficulty,
pol_epoch_nonce, pol_t0, pol_t1]`

The signing key behind `K_part_one`/`K_part_two` is the Ed25519 public
key of the all-`0x07` seed; its 32 bytes are the little-endian bytes of
the two halves concatenated.

## Version pin

The VK is tied to the trusted-setup ceremony in the circuits-bundle
release. It must match:

- `lbc-*-sys` tags in `logos-blockchain/Cargo.toml`
- `ExpectedCircuitsVersion` in `logos_chain/zk/circuits.nim`

Currently: **v0.5.6**. Bump all three together when the bundle moves.

## Regenerate

No generator is committed. Write a small harness in the reference
workspace, or adapt the `blend/proofs` prove/verify tests. They
already assemble these inputs.

Branch fixtures:

- Witness inputs: the crate's committed branch fixtures in
  `quota/fixtures.rs` (feature `unsafe-test-functions`). One set per
  selector.
- Signing key: the Ed25519 public key of the all-`0x07` seed.
- Output per branch: `proof_<branch>.bin` (160-byte wire
  `ProofOfQuota`) and `public_<branch>.json` (12 decimal signals, in
  the order above).

Core-set fixture: prove the core branch against a real two-member
registry. Pick two secret keys. Derive their zk-ids and the height-20
root. Prove with a chosen key index. Regenerate the proof, the public
signals, and `core_set_meta.json` together. The meta file keeps the
secrets out of the Nim tests.

Copy `verification_key.json` from the bundle's `poq/` directory of the
same release.
