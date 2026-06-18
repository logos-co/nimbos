# zksign test fixtures

nimbos ships only the zksign verifier — it has no Nim-side prover that
could generate a proof on the fly during tests. These three files are
committed fixtures (Rust-prover output) so the Nim verifier
(`tests/zk/test_zksign.nim`, `tests/ledger/test_cryptarchia.nim`) has
something to verify against.

These can be removed in favour of in-test proof generation once a
Nim-side zksign prover lands.

| File | Format |
|---|---|
| `verification_key.json` | snarkjs VK from circuits-bundle |
| `proof.json` | snarkjs `{pi_a, pi_b, pi_c, protocol}` |
| `public.json` | flat 33-element array: `[pk_0, …, pk_31, msg]` |

## Version pin

The VK is tied to the trusted-setup ceremony in the
circuits-bundle release. It must match:

- `lbc-*-sys` tags in `logos-blockchain/Cargo.toml`
- `ExpectedCircuitsVersion` in `logos_chain/zk/circuits.nim`

Currently: **v0.5.1**. Bump all three together when the bundle moves.

## Regenerate

Recipe (one-shot Rust `#[ignore]` test, copy outputs here):
see commit history or PR notes. Inputs are hardcoded as
`sks = [1, 0, …, 0]` signing `Poseidon2(b"nimbos-test-vector")`.
