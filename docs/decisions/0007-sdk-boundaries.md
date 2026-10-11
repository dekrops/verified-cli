# 0007. SDK boundaries

Status: accepted. Python is decided and built, in
[`dekrops/verified-python`](https://github.com/dekrops/verified-python);
TypeScript is not started.

## Rust

The library crates are the Rust SDK. Stable surface, in order of maturity:
`verified-canonical` (parse, encode, digest, signing input), then
`verified-protocol` types, then `verified-verifier::verify` and its report,
then `verified-verifier::issue` (ADR 0013).
Storage internals stay private to the workspace crate. The crates are
Apache-2.0. Nothing is published to crates.io without explicit authorization.

## Python and TypeScript

When this was proposed, neither existed, deliberately: bindings to an
unfinished core would freeze its mistakes. The contract an SDK's results
follow is the command-line JSON output, described in
[`docs/sdk/json-output.md`](../sdk/json-output.md). An SDK in any language:

- They expose domain operations (construct a claim, attach evidence
  references, assemble a package, verify, read a report), not hashing
  primitives.
- They are tested against the same public conformance corpus as the Rust
  core. No SDK carries its own informal copy of the protocol.
- **Issuing is not verifying.** An SDK that builds and signs a package has
  produced a claim. Its API and documentation must never present that as an
  independently verified outcome.
- Signing-key custody is the caller's responsibility and is documented as
  such; SDKs take a signer, not a private key file, where the platform allows.

## Python: decided

Rust-backed. `dekrops/verified-python` binds the five library crates through
PyO3, pinned to a tag of this repository (`v0.1.0` when this was written), and
ships one `abi3` wheel per platform. It is a separate repository with its own
releases; it is on PyPI as `verified-python`, which this repository's
publication policy does not cover.

It meets the points above:

- Its API is domain operations: verifier, trust registry, contract, evidence
  source, a work lifecycle.
- It runs the published corpus at the commit this repository pins, and
  fails rather than skips without it.
- It issues through `verified_verifier::issue`, and keeps the issuer's claim
  apart from a reproduced decision.
- It takes a `Signer`.

A binding should call this repository's library for anything the library
computes, and not restate it. Where a binding has had to write something
itself (the report as JSON, reading an anchor), the fix is to add it here,
in the next tag, and to delete the binding's copy.

## Open

TypeScript: Rust-backed, as Python, or pure. Upstream already has an
independent JavaScript verifier, which is an argument for the pure route
there. Weigh installation friction against the value of independence.
Package names are subject to availability.
