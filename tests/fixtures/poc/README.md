# poc test fixtures

Committed reference-prover output for the Nim proof-of-claim verifier
tests (`tests/zk/test_poc.nim`, `tests/ledger/test_poc_verifier.nim`).

| File | Format |
|---|---|
| `verification_key.json` | snarkjs VK from circuits-bundle |
| `proof.json` | snarkjs `{pi_a, pi_b, pi_c, protocol}` |
| `public.json` | flat 3-element array: `[voucher_nullifier, mantle_tx_hash, voucher_root]` |
| `sample.input.json` | the full witness input the proof was generated from |

## Version pin

Must match the `lbc-*-sys` tags in `logos-blockchain/Cargo.toml` and
`ExpectedCircuitsVersion` in `logos_chain/zk/circuits.nim`.
Currently: **v0.5.6**. Bump all three together when the bundle moves.

## Regenerate

No generator is committed. Write a small harness in the reference
workspace, or adapt the `poc` crate's prove/verify tests.

Re-prove the committed `sample.input.json`. The witness is fixed, so
`public.json` must come back byte-identical. Only `proof.json` and the
VK move with a release. Copy `verification_key.json` from the bundle's
`poc/` directory of the same release.
