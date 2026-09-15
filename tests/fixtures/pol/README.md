# pol test fixtures

Committed reference-prover output for the Nim proof-of-leadership
verifier tests (`tests/zk/test_pol.nim`, `tests/ledger/test_pol_verifier.nim`).

| File | Format |
|---|---|
| `verification_key.json` | snarkjs VK from circuits-bundle |
| `proof.json` | snarkjs `{pi_a, pi_b, pi_c, protocol}` |
| `public.json` | flat 9-element array: `[entropy_contribution, slot, epoch_nonce, t0, t1, aged_root, latest_root, leader_pk1, leader_pk2]` |

## Version pin

Must match the `lbc-*-sys` tags in `logos-blockchain/Cargo.toml` and
`ExpectedCircuitsVersion` in `logos_chain/zk/circuits.nim`.
Currently: **v0.5.6**. Bump all three together when the bundle moves.

## Regenerate

No generator is committed. Write a small harness in the reference
workspace, or adapt the `pol` crate's full-flow test. Use its witness
inputs verbatim.

Prove, then write `proof.json` in snarkjs shape and `public.json` as
9 decimal signals. Copy `verification_key.json` from the bundle's
`pol/` directory of the same release.

`tests/ledger/test_pol_verifier.nim` pins values from `public.json`,
for example the slot. New witness inputs need those pins updated.
