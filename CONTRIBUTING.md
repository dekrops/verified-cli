# Contributing

The repository is private and pre-release. External contributions open once
the license is approved (see `LICENSE`).

## The quality gate

Every change passes this, locally and in CI:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo deny check
cargo audit
```

The toolchain is pinned in `rust-toolchain.toml`. With access to the
conformance corpus, also run the tests as described in
[`conformance/README.md`](conformance/README.md).

## Rules that are not negotiable

- **Protocol behavior follows the specification and its vectors.** Never edit
  an expected outcome to make a test pass. A disagreement is a finding about
  the specification or the implementation; write it down in
  `docs/protocol/compatibility.md`.
- **Nothing from `dekrops/verified` is copied here** (source, specification
  text, schemas or fixtures) without the approval recorded in
  `docs/protocol/publication-review.md`.
- **No output may state more than was checked.** No single "valid" flag.
- **Refusal codes, exit codes and JSON member names are interfaces.**
  Changing one is a breaking change.
- **Dependencies earn their place.** A new one is justified in the pull
  request; `deny.toml` bans network and async runtimes outright.
- **Library crates do no I/O.** Files, the terminal and the process
  environment belong to `verified-cli`.
- `unsafe` is forbidden workspace-wide.

## Decisions

Architectural decisions are recorded in `docs/decisions/`. Add a record when a
change alters a boundary, a guarantee or a dependency policy.
