# Contributing

Verified CLI is open source under the [Apache License 2.0](LICENSE). The
repository is public and pre-release: nothing is tagged or published yet.

## Licensing of contributions

- Contributions are accepted under Apache-2.0, the license of the project
  (section 5 of the license: inbound is outbound).
- New source files start with `SPDX-License-Identifier: Apache-2.0`.
- Do not contribute code, specification text, fixtures or keys copied from
  the proprietary Verified platform or from anything else you cannot license
  under Apache-2.0. Implementing the same protocol is not a reason to copy.
- A new dependency must carry a license `deny.toml` allows. Adding a license
  to that list is a reviewed decision.
- Never commit credentials, production trust anchors or customer data. Test
  keys are derived from fixed seeds in the test support code and are used for
  nothing else.

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

A change to code that reads untrusted input should also be run through its
fuzz target for a while; [`fuzz/README.md`](fuzz/README.md) says how. The
fuzz targets are a separate workspace with their own toolchain, and are not
part of the gate above.

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
- **The protocol crates do no I/O.** `verified-canonical`, `-protocol`,
  `-contract` and `-verifier` read no file, clock or environment.
  `verified-workspace` touches only its own directory. The terminal, the
  clock and everything else belong to `verified-cli`.
- `unsafe` is forbidden workspace-wide.

## Library API changes

The five library crates follow semantic versioning from `v0.1.0`, and CI
compares their API with the last tag. A change that breaks it bumps the
workspace version in the same pull request and says what a consumer
changes. See [releasing](docs/development/releasing.md).

## Decisions

Architectural decisions are recorded in `docs/decisions/`. Add a record when a
change alters a boundary, a guarantee or a dependency policy.

## Review

Pull requests from branches of this repository are reviewed automatically by
Claude, in addition to the quality gate. What it checks, what its approval
means and how it is set up: [`docs/development/code-review.md`](docs/development/code-review.md).
