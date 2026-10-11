# 0014. Fuzz targets live outside the workspace, on a pinned nightly

Status: accepted and implemented in `fuzz/`.

## Context

The tool reads four kinds of untrusted input: packages, evidence statements,
claim registrations and registry logs, all through one JSON reader. Property
tests exercised the reader with arbitrary bytes and the verifier with
re-signed packages. Nothing was coverage-guided, and the registration code
had no generated input at all.

Coverage-guided fuzzing in Rust means libFuzzer through `cargo-fuzz`. That
collides with three things this project holds to:

- The toolchain is one pinned stable release. libFuzzer's instrumentation
  needs a nightly compiler.
- Dependencies are under an allow-list of four licenses. `libfuzzer-sys`
  is `(MIT OR Apache-2.0) AND NCSA`, and it compiles C++.
- `unsafe_code` is forbidden in the workspace. The `fuzz_target!` macro
  expands to an `extern "C"` entry point.

## Decision

- **A separate workspace.** `fuzz/` is a package with its own `[workspace]`,
  its own `Cargo.lock`, its own `rust-toolchain.toml` and its own
  `deny.toml`. The root workspace does not list it, so no command run at the
  root builds it, lints it or resolves its dependencies. The tool's
  dependency graph, license list and lints are unchanged.
- **A nightly pinned by date**, for the same reason the stable toolchain is
  pinned. Moving it is a reviewed change.
- **NCSA is allowed for `fuzz/` only.** It is a permissive license. Nothing
  under it is linked into the tool or distributed with it.
- **Targets call the library, not the binary**, at the functions the commands
  call, and assert properties where a cheap, certain one exists. A target
  never asserts something that depends on the trust configuration, because
  that is part of its input.
- **Seeds are generated from the published corpus**, not committed. The
  corpus is not copied into this repository; a script derives the seeds
  from a checkout of it.
- **CI runs every target for 30 seconds** on each pull request, and checks
  the fuzz dependencies with `cargo-deny`. Neither job is a required check:
  a nightly compiler or a runner image can break them for reasons unrelated
  to a change.

## Consequences

- Fuzzing needs `cargo-fuzz`, a second toolchain, a C++ compiler and `jq`.
  Building and testing the tool need none of them.
- The fuzzer cannot produce valid signatures, so code after a signature
  check is reached only through seeds and through rearranging whole signed
  objects. `fuzz/README.md` says so. A harness that signs what it generates
  would reach further; it does not exist.
- A short CI run is a build check and a regression check for the seeds. It
  is not evidence of robustness, and the documentation does not present it
  as such. No long campaign is scheduled; that would need somewhere to keep
  a growing corpus.
- A failure found by fuzzing becomes an ordinary test, so that the stable
  suite, which is the required check, keeps it fixed.

## Alternatives considered

- **More property tests on stable.** No new toolchain or license, but no
  coverage feedback: generated input rarely gets past the reader's first
  refusals. They stay, for what they are good at.
- **A fuzzer in pure Rust on stable.** None is maintained to the degree
  libFuzzer is, and each would still be a new dependency to review.
- **Adding `fuzz/` to the workspace.** It would put the nightly requirement,
  the C++ build and the NCSA license into every build of the tool.
