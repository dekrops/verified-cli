# Conformance

The Work Verification Protocol's conformance corpus is the measure of this
implementation: packages produced by another implementation, each with the
outcome every verifier must reach.

## Status: the corpus is not in this repository

The corpus lives in the private `dekrops/verified` repository, which grants no
license. Copying it here needs the approval described in
[`docs/protocol/publication-review.md`](../docs/protocol/publication-review.md).
Until then this directory holds no fixtures, and the tests that need them read
them from a path you supply.

## Running against the corpus

With a checkout of `dekrops/verified`:

```sh
VERIFIED_CONFORMANCE_DIR=/path/to/verified/test-vectors \
VERIFIED_CONFORMANCE_REQUIRED=1 \
  cargo test --workspace --locked -- --nocapture
```

- `VERIFIED_CONFORMANCE_DIR` is the directory containing
  `canonical-hash-v1.json` and `wvp/`.
- Without it the corpus tests print `skipped` and pass. With
  `VERIFIED_CONFORMANCE_REQUIRED=1` a missing corpus is a failure, so a run
  that claims conformance cannot skip silently.

Two tests use it:

| Test | Corpus | What it checks |
| --- | --- | --- |
| `verified-canonical/tests/shared_vectors.rs` | `canonical-hash-v1.json` | Canonical bytes and SHA-256 of every valid case; refusal of every invalid case. |
| `verified-verifier/tests/conformance.rs` | `wvp/v0.1`, `wvp/v0.2` | Container checks (protocol steps 1 to 6) on every vector. |

## Rules

- Expected outcomes come from the vectors. If this implementation disagrees
  with one, the specification is investigated; the expectation is never edited
  to make a test pass.
- A vector whose expected refusal belongs to a check this implementation does
  not have yet is counted as **deferred** and reported as such. It is never
  counted as conforming.
- Tests in this repository that do not need the corpus build their packages in
  process (`crates/verified-verifier/tests/support`). That data is synthetic
  and is not protocol test material.
